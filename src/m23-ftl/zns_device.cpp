/*
 * MIT License
Copyright (c) 2021 - current
Authors:  Animesh Trivedi
This code is part of the Storage System Course at VU Amsterdam
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include <asm-generic/errno.h>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <libnvme.h>
#include <mutex>
#include <nvme/ioctl.h>
#include <nvme/tree.h>
#include <nvme/types.h>
#include <nvme/util.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../common/unused.h"
#include "zns_device.h"

std::vector<long int> log_table;
std::vector<bool> data_zone_table; // data_zone_table: len = num data zones

struct ftl_params gftl_params;
struct user_zns_device gzns_dev;
std::thread gc_thread;
std::condition_variable cv;
std::mutex log_table_mut;
std::mutex gc_mut;
bool clear_lz;
bool gc_running; // set to true when gc it transferring data from log buffer to
                 // data zone
bool gc_shutdown;
bool if_init = false;

extern "C"
{

  // m1 code

  int
  ss_nvme_device_read (int fd, uint32_t nsid, uint64_t slba, uint16_t numbers,
                       void *buffer, uint64_t buf_size)
  {

    UNUSED (fd);
    UNUSED (nsid);

    int ret = -ENOSYS;
    ret = nvme_read (gftl_params.dev_fd, gftl_params.dev_nsid, slba,
                     numbers - 1, 0, 0, 0, 0, 0, buf_size, buffer, 0, nullptr);
    return ret;
  }

  int
  ss_nvme_device_write (int fd, uint32_t nsid, uint64_t slba, uint16_t numbers,
                        void *buffer, uint64_t buf_size)
  {
    UNUSED (fd);
    UNUSED (nsid);

    int ret = -ENOSYS;
    ret = nvme_write (gftl_params.dev_fd, gftl_params.dev_nsid, slba,
                      numbers - 1, 0, 0, 0, 0, 0, 0, buf_size, buffer, 0,
                      nullptr);
    return ret;
  }

  int
  ss_zns_device_zone_reset (int fd, uint32_t nsid, uint64_t slba)
  {

    UNUSED (fd);
    UNUSED (nsid);

    int ret = -ENOSYS;
    ret = nvme_zns_mgmt_send (gftl_params.dev_fd, gftl_params.dev_nsid, slba,
                              false, NVME_ZNS_ZSA_RESET, 0, nullptr);
    return ret;
  }

  // this does not take slba because it will return that
  int
  ss_zns_device_zone_append (int fd, uint32_t nsid, uint64_t zslba,
                             int numbers, void *buffer, uint32_t buf_size,
                             uint64_t *written_slba)
  {
    UNUSED (fd);
    UNUSED (nsid);

    int ret = -ENOSYS;
    void *ptr = (void *)written_slba;
    __u64 *written_slba_2 = (__u64 *)ptr;

    ret = nvme_zns_append (gftl_params.dev_fd, gftl_params.dev_nsid, zslba,
                           numbers - 1, 0, 0, 0, 0, buf_size, buffer, 0,
                           nullptr, written_slba_2);
    return ret;
  }

  void
  update_lba (uint64_t &write_lba, const uint32_t lba_size, const int count)
  {
    UNUSED (lba_size);
    write_lba += count;
  }

  int
  ss_nvme_device_io_with_mdts (int fd, uint32_t nsid, uint64_t slba,
                               uint16_t numbers, void *buffer,
                               uint64_t buf_size, uint64_t lba_size,
                               uint64_t mdts_size, bool read)
  {
    UNUSED (numbers);
    UNUSED (lba_size);
    UNUSED (mdts_size);
    UNUSED (fd);
    UNUSED (nsid);

    int ret = -ENOSYS, num_io, nlb;
    uint8_t *tbuf;

    nlb = gftl_params.mdts / gzns_dev.lba_size_bytes;
    tbuf = (uint8_t *)buffer;
    num_io = buf_size / gftl_params.mdts;

    if (read)
      {
        // modify to append
        for (int i = 0; i < num_io; i++)
          {
            ret = ss_nvme_device_read (gftl_params.dev_fd,
                                       gftl_params.dev_nsid, slba, nlb, tbuf,
                                       gftl_params.mdts);
            tbuf += gftl_params.mdts;
            update_lba (slba, 0, nlb);
          }
      }
    else
      {
        for (int i = 0; i < num_io; i++)
          {
            ret = ss_nvme_device_write (fd, nsid, slba, nlb, tbuf, lba_size);
            tbuf += gftl_params.mdts;
            update_lba (slba, 0, nlb);
          }
      }
    return ret;
  }

  // combines mdts_read,mdts_write and normal read, write
  int
  ss_nvme_device_c_mdts (uint64_t slba, uint16_t numbers, void *buffer,
                         uint64_t buf_size, bool read)
  {
    int ret = -ENOSYS;

    // mdts read is possible
    if (buf_size % gftl_params.mdts == 0)
      ret = ss_nvme_device_io_with_mdts (0, 0, slba, numbers, buffer, buf_size,
                                         0, 0, read);

    else if (buf_size % gftl_params.mdts != 0
             && buf_size / gftl_params.mdts > 0)
      {
        uint64_t tot_mdts_blocks = buf_size / gftl_params.mdts;
        uint64_t tot_blks_in_mdts
            = gftl_params.mdts
              / gzns_dev.lba_size_bytes; // total number of lbas in mdts size
        uint16_t mdts_numbers = numbers - (tot_mdts_blocks * tot_blks_in_mdts);
        uint64_t mdts_read_size = tot_mdts_blocks * gftl_params.mdts;

        ret = ss_nvme_device_io_with_mdts (0, 0, slba, mdts_numbers, buffer,
                                           mdts_read_size, 0, 0, read);
        uint8_t *t_buf = ((uint8_t *)buffer) + (mdts_read_size);
        uint64_t t_buf_size = buf_size - mdts_read_size;
        if (read)
          ret = ss_nvme_device_read (0, 0, slba + mdts_numbers,
                                     numbers - mdts_numbers, t_buf,
                                     t_buf_size);
        else
          ret = ss_nvme_device_write (0, 0, slba + mdts_numbers,
                                      numbers - mdts_numbers, t_buf,
                                      t_buf_size);
      }
    else
      {
        if (read)
          ret = ss_nvme_device_read (0, 0, slba, numbers, buffer, buf_size);
        else
          ret = ss_nvme_device_write (0, 0, slba, numbers, buffer, buf_size);
      }
    return ret;
  }

  // see 5.15.2.2 Identify Controller data structure (CNS 01h)
  // see how to pass any number of variables in a C/C++ program
  // https://stackoverflow.com/questions/1579719/variable-number-of-parameters-in-function-in-c
  // feel free to pass any relevant function parameter to this function extract
  // MDTS you must return the MDTS as the return value of this function
  uint64_t
  get_mdts_size (int count, ...)
  {
    // doesn't work with m1, works with m2 as right device name is sent

    va_list args;
    va_start (args, count);

    const char *dev_name = va_arg (args, char *);
    printf ("%s", dev_name);
    const int dev_fd = va_arg (args, int);

    char path[512];
    void *bar;
    nvme_ns_t n = NULL;

    // taken from nvme_cli
    nvme_root_t r = nvme_scan (NULL);
    nvme_ctrl_t c = nvme_scan_ctrl (r, dev_name);

    if (c)
      {
        snprintf (path, sizeof (path), "%s/device/resource0",
                  nvme_ctrl_get_sysfs_dir (c));
        nvme_free_ctrl (c);
      }
    else
      {
        n = nvme_scan_namespace (dev_name);

        if (!n)
          {
            fprintf (stderr, "Unable to find %s\n", dev_name);
          }
        snprintf (path, sizeof (path), "%s/device/device/resource0",
                  nvme_ns_get_sysfs_dir (n));
        nvme_free_ns (n);
      }

    int fd = open (path, O_RDONLY);
    if (fd < 0)
      {
        printf ("%s did not find a pci resource, open failed \n", dev_name);
      }

    nvme_id_ctrl zns_id_ctrl;
    nvme_identify_ctrl (dev_fd, &zns_id_ctrl);

    bar = mmap (NULL, getpagesize (), PROT_READ, MAP_SHARED, fd, 0);
    close (fd);
    uint64_t cap = nvme_mmio_read64 (bar);
    // printf("The cap is %lu\n", cap);
    __u32 mpsmin = ((__u8 *)&cap)[6] & 0x0f;
    mpsmin = (1 << (12 + mpsmin));
    // printf("The mpsmin is %u\n", mpsmin);
    int mdts = mpsmin * (1 << (zns_id_ctrl.mdts - 1));
    // printf("The mdts is %i\n", mdts);
    munmap (bar, getpagesize ());
    return mdts;
  }

  // m1 code

  struct read_log_entry
  {
    uint64_t slba;
    uint64_t nlb;
    uint64_t buffer_offset;
  };

  // returns the logical zone where the virtual address belongs in
  uint64_t
  ftl_get_va_dz (uint64_t address)
  {
    uint64_t zone_size_bytes
        = gftl_params.blks_per_zone * gzns_dev.lba_size_bytes;
    return (address / zone_size_bytes) + gftl_params.st_dz;
  }

  // get the slba for an address' datazone
  uint64_t
  ftl_get_va_dz_slba (uint64_t address)
  {
    uint64_t dz = ftl_get_va_dz (address);
    return dz * gftl_params.blks_per_zone;
  }

  // get the data zone lba for an address
  uint64_t
  ftl_get_va_dz_lba (uint64_t address)
  {
    uint64_t zone_lba_offset
        = (address % (gzns_dev.lba_size_bytes * gftl_params.blks_per_zone))
          / gzns_dev.lba_size_bytes;
    return ftl_get_va_dz_slba (address) + zone_lba_offset;
  }

  // get the number of free logical blocks in the log zone
  int
  ftl_get_lz_free_lb ()
  {
    if (gftl_params.wlba > gftl_params.tail_lba)
      return (gftl_params.tail_lba - gftl_params.lz_slba)
             + (gftl_params.lz_elba - gftl_params.wlba);
    return gftl_params.tail_lba - gftl_params.wlba;
  }

  void
  stack_buffer (std::vector<read_log_entry> log_table_rd, void *src,
                void *dest)
  {
    for (uint i = 0; i < log_table_rd.size (); i++)
      {
        uint64_t offset = log_table_rd[i].buffer_offset;
        uint64_t size = log_table_rd[i].nlb * gzns_dev.lba_size_bytes;

        uint8_t *ts_buf = ((uint8_t *)src) + offset;
        uint8_t *td_buf = ((uint8_t *)dest) + offset;

        memcpy (td_buf, ts_buf, size);
      }
  }

  // updates log table with addresses or -1
  void
  ftl_update_log_table (uint64_t nlb, uint64_t address, uint64_t slba,
                        bool set_false)
  {
    if (set_false)
      {
        for (uint i = slba; i < slba + nlb; i++)
          {
            log_table[i] = -1;
          }
      }
    else
      {
        for (uint i = slba; i < slba + nlb; i++)
          {
            log_table[i] = (long int)address;
            address += gzns_dev.lba_size_bytes;
          }
      }
  }

  int
  ftl_read_from_log_zone (void *buffer, std::vector<read_log_entry> read_logs)
  {
    int ret = -ENOSYS;

    for (uint i = 0; i < read_logs.size (); i++)
      {
        uint64_t numbers = read_logs[i].nlb;
        uint64_t slba = read_logs[i].slba;
        uint8_t *t_buf = ((uint8_t *)buffer) + read_logs[i].buffer_offset;
        uint64_t buf_size = numbers * gzns_dev.lba_size_bytes;
        ret = ss_nvme_device_c_mdts (slba, numbers, t_buf, buf_size, true);
      }

    return ret;
  }

  // func notifies the gc thread if zones need clearing, updates the wlba
  // performs write on a circular log zone
  int
  ftl_write_to_log_zone (uint64_t address, void *buffer, uint64_t size)
  {
    int ret = -ENOSYS;
    uint64_t free_log_lbs, nlb, slba;
    free_log_lbs = ftl_get_lz_free_lb (); // get total free blocks

    // clear log lbs until the minimum requirement for log zones is hit
    while (free_log_lbs <= gftl_params.gc_wmark_lb)
      {
        {
          std::unique_lock<std::mutex> lk (gc_mut);
          clear_lz = true;
        }
        cv.notify_one (); // notify gc to run, wait until reset
        {
          std::unique_lock<std::mutex> lk (gc_mut);
          cv.wait (lk, [] { return !clear_lz; });
        }

        free_log_lbs = ftl_get_lz_free_lb ();
      }

    log_table_mut.lock ();

    // when log zone is not sequential
    if (gftl_params.wlba > gftl_params.tail_lba)
      {

        slba = gftl_params.wlba;

        // total writable size from wlba - lz_elba
        uint64_t welba_wsize
            = (gftl_params.lz_elba - slba) * gzns_dev.lba_size_bytes;

        if (size <= welba_wsize)
          {
            nlb = size / gzns_dev.lba_size_bytes;
            ret = ss_nvme_device_c_mdts (slba, nlb, buffer, size, false);

            // on append will have to be pushed to ss_nvme_device_c_mdts
            ftl_update_log_table (nlb, address, slba, true);
            gftl_params.wlba += nlb;
          }
        else
          {
            // circular log zone insert
            slba = gftl_params.wlba;

            nlb = gftl_params.lz_elba - gftl_params.wlba;
            uint64_t t_size = nlb * gzns_dev.lba_size_bytes;
            ret = ss_nvme_device_c_mdts (slba, nlb, buffer, t_size, false);
            ftl_update_log_table (nlb, address, slba, true);

            // point to remaining buffer
            uint8_t *t_buf = ((uint8_t *)buffer) + t_size;
            uint64_t t_address = address + t_size;
            t_size = size - t_size;

            // write remaining buffer to start of log zone
            slba = gftl_params.lz_slba;
            nlb = t_size / gzns_dev.lba_size_bytes;
            ret = ss_nvme_device_c_mdts (slba, nlb, t_buf, t_size, false);
            ftl_update_log_table (nlb, t_address, slba, true);
            gftl_params.wlba = gftl_params.lz_slba + nlb;
          }
      }
    else
      {
        // write normally as log zone is currently sequential
        slba = gftl_params.wlba;
        nlb = size / gzns_dev.lba_size_bytes;
        ret = ss_nvme_device_c_mdts (slba, nlb, buffer, size, false);
        ftl_update_log_table (nlb, address, slba, true);
        gftl_params.wlba += nlb;
      }

    if (gftl_params.wlba == gftl_params.lz_elba)
      gftl_params.wlba = gftl_params.lz_slba;

    log_table_mut.unlock ();
    return ret;
  }

  // read from data_zone using virtual address
  int
  ftl_read_from_data_zone (uint64_t address, void *buffer, int size)
  {
    int ret;
    uint64_t nlb, slba;
    nlb = size / gzns_dev.lba_size_bytes;
    slba = ftl_get_va_dz_lba (address);
    ret = ss_nvme_device_c_mdts (slba, nlb, buffer, size, true);
    return ret;
  }

  // write to one full data zone
  int
  ftl_write_to_data_zone (uint64_t address, void *buffer, int size)
  {
    int ret;
    uint64_t nlb, slba;
    nlb = size / gzns_dev.lba_size_bytes;
    slba = ftl_get_va_dz_slba (address);
    ret = ss_nvme_device_c_mdts (slba, nlb, buffer, size, false);
    return ret;
  }

  void
  __create_mapping (
      std::unordered_map<uint64_t, read_log_entry> &log_table_map,
      uint64_t address, uint64_t slba, uint64_t elba, uint64_t size,
      std::vector<long int> log_table_l)
  {

    uint64_t end_addr = address + (uint64_t)size;

    for (uint i = slba; i < elba; i++)
      {
        uint64_t c_addr = log_table_l[i];

        // when address in log zone belongs to the read address space
        if (c_addr >= address && c_addr < end_addr)
          {
            struct read_log_entry t_entry;
            t_entry.slba = i;
            t_entry.nlb = i;
            t_entry.buffer_offset = address - c_addr;

            if (log_table_map.count (address) > 0)
              log_table_map[address] = t_entry;
            else
              log_table_map.insert (std::make_pair (address, t_entry));
          }
      }
  }

  // creates a log table mapping for an address space using the given log table
  void
  create_log_table_mapping_for_va (std::vector<read_log_entry> &log_table_rd,
                                   uint64_t address, uint64_t slba,
                                   uint64_t tail_lba, uint64_t size,
                                   std::vector<long int> log_table_l,
                                   bool circ)
  {

    std::unordered_map<uint64_t, read_log_entry> log_table_map;
    uint64_t tslba, telba;
    uint64_t end_address = address + size;

    if (slba > tail_lba && circ)
      {
        tslba = slba;
        telba = gftl_params.lz_elba;
        __create_mapping (log_table_map, address, tslba, telba, size,
                          log_table_l);
        tslba = gftl_params.lz_slba;
        telba = tail_lba;
        __create_mapping (log_table_map, address, tslba, telba, size,
                          log_table_l);
      }

    else if (slba < tail_lba && tail_lba != gftl_params.lz_elba && circ)
      {
        tslba = tail_lba;
        telba = gftl_params.lz_elba;
        __create_mapping (log_table_map, address, tslba, telba, size,
                          log_table_l);
        tslba = gftl_params.lz_slba;
        telba = slba;
        __create_mapping (log_table_map, address, tslba, telba, size,
                          log_table_l);
      }

    else
      __create_mapping (log_table_map, address, slba, tail_lba, size,
                        log_table_l);

    for (uint i = address; i < end_address; i += gzns_dev.lba_size_bytes)
      {
        if (log_table_map.count (address) > 0)
          {
            if (log_table_rd.size () == 0)
              log_table_rd.push_back (log_table_map[i]);

            else
              {
                uint64_t lst_index = log_table_rd.size () - 1;
                uint64_t lst_slba = log_table_rd[lst_index].slba;
                uint64_t lst_nlb = log_table_rd[lst_index].nlb;
                uint64_t c_slba = log_table_map[i].slba;

                if (lst_slba + lst_nlb == c_slba)
                  log_table_rd[lst_index].nlb += 1;
                else
                  log_table_rd.push_back (log_table_map[i]);
              }
          }
      }
  }

  // creates a list of data zones that have data in the reset log zone
  void
  create_dz_read_list (std::vector<bool> &dz_read,
                       std::vector<uint64_t> log_table_c, int slba)
  {

    for (uint i = slba; i < slba + gftl_params.blks_per_zone; i++)
      {
        uint64_t addr = log_table_c[i];
        uint64_t dz = ftl_get_va_dz (addr);
        dz_read[dz] = true;
      }
  }

  int
  ftl_reset_lz (void *lz_buf)
  {
    int ret = -ENOSYS;
    uint64_t nlb, zone_size_bytes, lzslba;

    nlb = gzns_dev.tparams.zns_zone_capacity / gzns_dev.lba_size_bytes;
    zone_size_bytes = gzns_dev.tparams.zns_zone_capacity;
    lzslba = gftl_params.target_lzslba;

    // reset log table
    ftl_update_log_table (nlb, 0, lzslba, true);

    // read from log zone
    ret = ss_nvme_device_c_mdts (lzslba, nlb, lz_buf, zone_size_bytes, true);

    // reset log zone
    ret = nvme_zns_mgmt_send (gftl_params.dev_fd, gftl_params.dev_nsid, lzslba,
                              false, NVME_ZNS_ZSA_RESET, 0, nullptr);
    // update tail pointer
    if (gftl_params.tail_lba == gftl_params.lz_elba)
      gftl_params.tail_lba = gftl_params.lz_slba + gftl_params.blks_per_zone;
    else
      gftl_params.tail_lba = gftl_params.tail_lba + gftl_params.blks_per_zone;

    // update next reset log zone target
    if (lzslba == gftl_params.lz_elba - gftl_params.blks_per_zone)
      gftl_params.target_lzslba = gftl_params.lz_slba;
    else
      gftl_params.target_lzslba = lzslba + gftl_params.blks_per_zone;

    return ret;
  }

  // create a table of which data zones to update using the log buffer
  void
  create_dz_update_table (std::vector<bool> &dz_update_table,
                          std::vector<long int> log_table_c, int lzslba)
  {

    uint64_t nlb = gftl_params.blks_per_zone;
    for (uint i = lzslba; i < lzslba + nlb; i++)
      {
        int dz_to_upd = ftl_get_va_dz (log_table_c[i]);
        dz_update_table[dz_to_upd] = true;
      }
  }

  // write a log zone buffer to data zone
  int
  ftl_write_lz_buf_dz (uint64_t lzslba, std::vector<long int> log_table_c,
                       std::vector<uint8_t> lz_buf)
  {
    int nlb, zone_size, ret;
    std::vector<bool> dz_update_table;

    nlb = gftl_params.blks_per_zone;
    zone_size = gzns_dev.tparams.zns_zone_capacity;
    dz_update_table = std::vector<bool> (gftl_params.tot_zones);

    create_dz_update_table (dz_update_table, log_table_c, lzslba);

    // iterating though zones we need to read
    for (uint32_t i = gftl_params.st_dz; i < dz_update_table.size (); i++)
      {
        if (dz_update_table[i])
          {
            uint64_t va = (i - gftl_params.st_dz) * zone_size;
            std::vector<uint8_t> dz_buf;
            dz_buf.resize (zone_size, 0);

            // read from data zone if data exists
            if (data_zone_table[i])
              ftl_read_from_data_zone (va, dz_buf.data (), zone_size);

            // add log zone entries to the data zone buffer
            std::vector<read_log_entry> read_logs;
            create_log_table_mapping_for_va (read_logs, va, lzslba,
                                             lzslba + nlb, zone_size,
                                             log_table_c, false);

            stack_buffer (read_logs, lz_buf.data (), dz_buf.data ());

            // reset the datazone and write fresh data to it
            ret = nvme_zns_mgmt_send (gftl_params.dev_fd, gftl_params.dev_nsid,
                                      (__u64)i * nlb, false,
                                      NVME_ZNS_ZSA_RESET, 0, nullptr);

            ftl_write_to_data_zone (va, dz_buf.data (), zone_size);
            data_zone_table[i] = true;
          }
      }

    // allow reads from datazone
    gc_running = false;
    cv.notify_all ();

    return ret;
  }

  int
  deinit_ss_zns_device (struct user_zns_device *my_dev)
  {
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this
    // function

    gc_shutdown = true;
    clear_lz = true;
    cv.notify_one (); // run gc one more time and exit

    gc_thread.join ();
    free (my_dev);

    // push metadata onto the device
    return ret;
  }

  void
  gc_main ()
  {
    uint64_t ct_lzslba;

    while (true && !gc_shutdown)
      {
        std::unique_lock<std::mutex> lk (gc_mut);

        cv.wait (lk, [] { return clear_lz; });
        gc_running = true;
        std::vector<long int> log_table_c;
        std::vector<uint8_t> lz_buffer;
        lz_buffer.resize (gzns_dev.tparams.zns_zone_capacity);

        log_table_mut.lock ();
        ct_lzslba = gftl_params.target_lzslba;
        ftl_reset_lz (lz_buffer.data ());
        clear_lz = false;
        log_table_c = log_table;
        log_table_mut.unlock ();

        lk.unlock ();
        cv.notify_all (); // notify write thread to start writing after reset

        ftl_write_lz_buf_dz (ct_lzslba, log_table_c, lz_buffer);
      }
  }

  int
  init_ss_zns_device (struct zdev_init_params *params,
                      struct user_zns_device **my_dev)
  {

    if (if_init)
      return 0;

    if_init = true;
    int ret = -ENOSYS;
    struct nvme_id_ns ns;
    nvme_zns_id_ns zns_ns;
    *my_dev = &gzns_dev;
    struct nvme_zone_report zns_report;

    // Open device and setup zns_dev_params
    gftl_params.dev_fd = nvme_open (params->name);
    ret = nvme_get_nsid ((int)gftl_params.dev_fd,
                         (__u32 *)&gftl_params.dev_nsid);

    // Get logical block size
    ret = nvme_identify_ns (gftl_params.dev_fd, gftl_params.dev_nsid, &ns);
    gzns_dev.tparams.zns_lba_size = 1 << ns.lbaf[(ns.flbas & 0xf)].ds;
    gzns_dev.lba_size_bytes = gzns_dev.tparams.zns_lba_size;

    // setup up thread variables
    clear_lz = false;
    gc_running = false;
    gc_shutdown = false;

    // check for persistency (copy ftl parameters)
    void *p_buf = malloc (gzns_dev.lba_size_bytes);
    ss_nvme_device_read (gftl_params.dev_fd, gftl_params.dev_nsid, 0x00, 1,
                         p_buf, gzns_dev.lba_size_bytes);
    memcpy (&gftl_params, p_buf, sizeof (ftl_params));
    free (p_buf);

    const char pcheck[] = "2023stos";

    if (strcmp (pcheck, &gftl_params.ftl_status[0]))
      {

        // copy log table
        void *t_log_buf = malloc (gftl_params.log_table_size);
        uint t_numbers = gftl_params.log_table_size / gzns_dev.lba_size_bytes;
        ss_nvme_device_read (gftl_params.dev_fd, gftl_params.dev_nsid,
                             gftl_params.slba_log_table, t_numbers, t_log_buf,
                             gftl_params.log_table_size);

        uint64_t mem_lzt_size
            = gftl_params.blks_per_zone * gftl_params.log_zones * 8;
        memcpy (log_table.data (), t_log_buf, mem_lzt_size);
        free (t_log_buf);

        // copy dz bit table

        return 0;
      }

    strcpy (&gftl_params.ftl_status[0], pcheck);
    gftl_params.wlba = 0x00;
    gftl_params.lz_slba = gftl_params.wlba;
    gftl_params.target_lzslba = 0x00;
    gftl_params.log_zones = params->log_zones;

    // getting mdts
    int mdts = get_mdts_size (2, params->name, gftl_params.dev_fd);
    gftl_params.mdts = mdts;

    // Reset device
    ret = nvme_zns_mgmt_send (gftl_params.dev_fd, gftl_params.dev_nsid,
                              (__u64)0x00, true, NVME_ZNS_ZSA_RESET, 0,
                              nullptr);

    // getting total zones in the namespace
    ret = nvme_zns_mgmt_recv (
        gftl_params.dev_fd, (uint32_t)gftl_params.dev_nsid, 0,
        NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL, 0,
        sizeof (zns_report), (void *)&zns_report);
    gzns_dev.tparams.zns_num_zones
        = le64_to_cpu (zns_report.nr_zones) - params->log_zones;

    // getting number of blocks per zone
    ret = nvme_zns_identify_ns (gftl_params.dev_fd,
                                (uint32_t)gftl_params.dev_nsid, &zns_ns);
    gftl_params.blks_per_zone
        = le64_to_cpu (zns_ns.lbafe[(ns.flbas & 0xf)].zsze);

    gzns_dev.tparams.zns_zone_capacity
        = gftl_params.blks_per_zone
          * gzns_dev.tparams.zns_lba_size; // number of bytes in a zone

    gftl_params.gc_wmark_lb
        = params->gc_wmark
          * gftl_params.blks_per_zone; // gc_wmark logical block address

    gftl_params.tail_lba
        = gftl_params.lz_slba
          + params->log_zones
                * gftl_params.blks_per_zone; // tail lba set to end of log zone

    gftl_params.lz_elba = gftl_params.tail_lba;

    gzns_dev.capacity_bytes
        = gzns_dev.tparams.zns_zone_capacity
          * gzns_dev.tparams.zns_num_zones; // writable size of device in bytes

    // Start the GC thread and init the conditional variables
    gc_thread = std::thread (gc_main);

    return ret;
  }

  int
  zns_udevice_read (struct user_zns_device *my_dev, uint64_t address,
                    void *buffer, uint32_t size)
  {
    UNUSED (my_dev);

    int ret = -ENOSYS;
    std::vector<read_log_entry> log_table_rd;

    log_table_mut.lock ();
    uint64_t dz = ftl_get_va_dz (address);

    // read from data zone if entry exists
    if (data_zone_table[dz])
      {
        ret = ftl_read_from_data_zone (address, buffer, size);
      }

    std::unique_lock<std::mutex> lk (gc_mut);
    cv.wait (lk, [] { return !gc_running; });

    // read from log zone (using virtual address)
    create_log_table_mapping_for_va (log_table_rd, address,
                                     gftl_params.lz_slba, gftl_params.lz_elba,
                                     size, log_table, true);

    ret = ftl_read_from_log_zone (buffer, log_table_rd);

    log_table_mut.unlock ();
    return ret;
  }

  int
  zns_udevice_write (struct user_zns_device *my_dev, uint64_t address,
                     void *buffer, uint32_t size)
  {
    UNUSED (my_dev);
    int ret = -ENOSYS;

    // write to end of log zone
    ret = ftl_write_to_log_zone (address, buffer, size);
    return ret;
  }
}
