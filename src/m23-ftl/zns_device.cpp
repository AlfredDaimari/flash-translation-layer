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

#include "zns_device.h"

#include <asm-generic/errno.h>
#include <fcntl.h>
#include <libnvme.h>
#include <nvme/ioctl.h>
#include <nvme/tree.h>
#include <nvme/types.h>
#include <nvme/util.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../common/unused.h"

std::vector<long long int> log_table;
std::vector<bool> data_zone_table;  // data_zone_table: len = num data zones

std::thread gc_thread;
std::condition_variable cv;
std::mutex log_table_mutex;
std::mutex gc_mutex;
bool lz1_cleared;
bool clear_lz1;
bool gc_shutdown;

extern "C" {

// m1 code

int ss_nvme_device_read(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers,
                        void *buffer, uint64_t buf_size) {
  int ret = -ENOSYS;
  // this is to supress gcc warnings, remove it when you complete this function
  ret = nvme_read(fd, nsid, slba, numbers - 1, 0, 0, 0, 0, 0, buf_size, buffer,
                  0, nullptr);
  return ret;
}

int ss_nvme_device_write(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers,
                         void *buffer, uint64_t buf_size) {
  int ret = -ENOSYS;
  ret = nvme_write(fd, nsid, slba, numbers - 1, 0, 0, 0, 0, 0, 0, buf_size,
                   buffer, 0, nullptr);
  return ret;
}

int ss_zns_device_zone_reset(int fd, uint32_t nsid, uint64_t slba) {
  int ret = -ENOSYS;
  ret =
      nvme_zns_mgmt_send(fd, nsid, slba, false, NVME_ZNS_ZSA_RESET, 0, nullptr);
  return ret;
}

// this does not take slba because it will return that
int ss_zns_device_zone_append(int fd, uint32_t nsid, uint64_t zslba,
                              int numbers, void *buffer, uint32_t buf_size,
                              uint64_t *written_slba) {
  // see section 4.5 how to write an append command

  int ret = -ENOSYS;
  void *ptr = (void *)written_slba;
  __u64 *written_slba_2 = (__u64 *)ptr;

  ret = nvme_zns_append(fd, nsid, zslba, numbers - 1, 0, 0, 0, 0, buf_size,
                        buffer, 0, nullptr, written_slba_2);
  return ret;
}

void update_lba(uint64_t &write_lba, const uint32_t lba_size, const int count) {
  UNUSED(lba_size);
  write_lba += count;
}

int ss_nvme_device_io_with_mdts(int fd, uint32_t nsid, uint64_t slba,
                                uint16_t numbers, void *buffer,
                                uint64_t buf_size, uint64_t lba_size,
                                uint64_t mdts_size, bool read) {
  UNUSED(numbers);

  int ret = -ENOSYS, num_io, io_size, nlb;
  uint8_t *buf;
  // this is to supress gcc warnings, remove it when you complete this function
  if (mdts_size < buf_size) {
    num_io = buf_size / mdts_size;
    io_size = mdts_size;
  } else {
    num_io = 1;
    io_size = buf_size;
  }

  nlb = io_size / lba_size;
  buf = (uint8_t *)buffer;

  if (read) {
    // printf("starting lba is %i, total lba is %i\n", slba, numbers);
    for (int i = 0; i < num_io; i++) {
      ret = ss_nvme_device_read(fd, nsid, slba, nlb, buf, io_size);
      buf += io_size;
      update_lba(slba, lba_size, nlb);
    }
  } else {
    for (int i = 0; i < num_io; i++) {
      ret = ss_nvme_device_write(fd, nsid, slba, nlb, buf, io_size);
      buf += io_size;
      update_lba(slba, lba_size, nlb);
    }
  }
  return ret;
}

// see 5.15.2.2 Identify Controller data structure (CNS 01h)
// see how to pass any number of variables in a C/C++ program
// https://stackoverflow.com/questions/1579719/variable-number-of-parameters-in-function-in-c
// feel free to pass any relevant function parameter to this function extract
// MDTS you must return the MDTS as the return value of this function
uint64_t get_mdts_size(int count, ...) {
  // doesn't work with m1, works with m2 as right device name is sent

  va_list args;
  va_start(args, count);

  const char *dev_name = va_arg(args, char *);
  printf("%s", dev_name);
  const int dev_fd = va_arg(args, int);

  char path[512];
  void *bar;
  nvme_ns_t n = NULL;

  // taken from nvme_cli
  nvme_root_t r = nvme_scan(NULL);
  nvme_ctrl_t c = nvme_scan_ctrl(r, dev_name);

  if (c) {
    snprintf(path, sizeof(path), "%s/device/resource0",
             nvme_ctrl_get_sysfs_dir(c));
    nvme_free_ctrl(c);
  } else {
    n = nvme_scan_namespace(dev_name);

    if (!n) {
      fprintf(stderr, "Unable to find %s\n", dev_name);
    }
    snprintf(path, sizeof(path), "%s/device/device/resource0",
             nvme_ns_get_sysfs_dir(n));
    nvme_free_ns(n);
  }

  // printf("Path is %s\n", path);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("%s did not find a pci resource, open failed \n", dev_name);
  }

  nvme_id_ctrl zns_id_ctrl;
  nvme_identify_ctrl(dev_fd, &zns_id_ctrl);

  bar = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
  close(fd);
  uint64_t cap = nvme_mmio_read64(bar);
  // printf("The cap is %lu\n", cap);
  __u32 mpsmin = ((__u8 *)&cap)[6] & 0x0f;
  mpsmin = (1 << (12 + mpsmin));
  // printf("The mpsmin is %u\n", mpsmin);
  int mdts = mpsmin * (1 << (zns_id_ctrl.mdts - 1));
  // printf("The mdts is %i\n", mdts);
  munmap(bar, getpagesize());
  return mdts;
}

// m1 code

// returns the logical zone where the virtual address belongs in
int ss_get_dz(uint64_t address, uint64_t zone_size_in_bytes,
              int num_of_log_zones) {
  return static_cast<int>(address / zone_size_in_bytes) + num_of_log_zones;
}

// get the data zone lba for an address
int ss_get_ad_dz_lba(uint64_t address, uint64_t zone_size_in_bytes,
                     int lba_size, int num_of_log_zones) {
  int dz_lba = static_cast<int>(address / lba_size);
  int log_lba_offset = (zone_size_in_bytes * num_of_log_zones) / lba_size;
  return log_lba_offset + dz_lba;
}

// get the slba for an address' datazone
int ss_get_dz_slba(uint64_t address, uint64_t zone_size_in_bytes, int lba_size,
                   int num_of_log_zones) {
  // bpz = num of blocks per zone
  int bpz = zone_size_in_bytes / lba_size;
  int dz = static_cast<int>(address / zone_size_in_bytes) + num_of_log_zones;
  return dz * bpz;
}

// number of free logical blocks in log zones
int ss_get_logzone_free_lb(int wlba, int tail_lba, int end_lba) {
  if (wlba > tail_lba) {
    return tail_lba + (end_lba - wlba);
  }
  return tail_lba - wlba;
}

// updates log table with addresses or -1
void ss_update_log_table(int nlb, uint64_t address, int slba, uint32_t lba_size,
                         bool set_false) {
  // adding mappings to the log table

    if (set_false) {
    for (int i = slba; i < slba + nlb; i++) {
      log_table[i] = -1;
    }
  } else {
    for (int i = slba; i < slba + nlb; i++) {
      log_table[i] = (long long int)
          address;  // update both wlba and address by logical block size
      address += lba_size;
    }
  }
}

// returns the first valid mapping in the log table for an address space
int get_valid_address_from_log_table(
    uint64_t address, uint64_t end_address, uint32_t lba_size,
    std::unordered_map<uint64_t, uint64_t> log_table_map) {
  uint64_t current_address = address;

  while (current_address != end_address) {
    if (log_table_map.count(current_address) > 0) {
      return current_address;
    }
    current_address += lba_size;
  }

  return current_address;
}

// more than one block is read only when two contiguos vb is contiguous in
// the log zone (can be optimized much better) func reads from log zone using
// an slba or address space log_table_map <- this contains a mapping of
// addresses to lbas

int ss_read_from_log_zone(
    user_zns_device *my_dev, uint64_t address, int slba, void *buffer, int size,
    int nlb, bool read_address,
    std::unordered_map<uint64_t, uint64_t> log_table_map) {
  int ret;

  struct zns_dev_params *zns_dev = (struct zns_dev_params *)my_dev->_private;

  // read virtual address blocks in the log zone
  if (read_address) {
    int cur_address = address, fst_cog_address, next_address,
        end_address = address + size;
    uint8_t *buf_t;
    int t_nlb = 1, buf_dz_fst_offset;

    // finding the first valid virtual address in the log zone
    cur_address = get_valid_address_from_log_table(
        address, end_address, (uint32_t)my_dev->lba_size_bytes, log_table_map);
    if (cur_address == end_address) return 0;

    fst_cog_address = cur_address;
    buf_dz_fst_offset =
        ss_get_ad_dz_lba(address, my_dev->tparams.zns_zone_capacity,
                         my_dev->lba_size_bytes, zns_dev->log_zones);

    while (cur_address != end_address) {
      next_address = cur_address + my_dev->lba_size_bytes;

      // when the next address is not present in the log zone
      if (log_table_map.count(next_address) == 0) {
        // getting position of address in buffer

        int buf_lba_cur_offset =
            ss_get_ad_dz_lba(fst_cog_address, my_dev->tparams.zns_zone_capacity,
                             my_dev->lba_size_bytes, zns_dev->log_zones) -
            buf_dz_fst_offset;
        buf_t =
            ((uint8_t *)buffer) + buf_lba_cur_offset * my_dev->lba_size_bytes;

        ret = ss_nvme_device_io_with_mdts(
            zns_dev->dev_fd, zns_dev->dev_nsid, log_table_map[fst_cog_address],
            t_nlb, buf_t, t_nlb * my_dev->lba_size_bytes,
            my_dev->lba_size_bytes, zns_dev->mdts, true);

        cur_address = get_valid_address_from_log_table(
            next_address, end_address, (uint32_t)my_dev->lba_size_bytes,
            log_table_map);
        fst_cog_address = cur_address;
        t_nlb = 1;
      }

      // when the current and next logical blocks are contiguous
      else if ((log_table_map[next_address] - log_table_map[cur_address]) ==
               1) {
        t_nlb += 1;
        cur_address = next_address;

      } else {
        // virtual address blocks in log zone are not contiguous
        int buf_lba_cur_offset =
            ss_get_ad_dz_lba(fst_cog_address, my_dev->tparams.zns_zone_capacity,
                             my_dev->lba_size_bytes, zns_dev->log_zones) -
            buf_dz_fst_offset;
        buf_t =
            ((uint8_t *)buffer) + buf_lba_cur_offset * my_dev->lba_size_bytes;

        ret = ss_nvme_device_io_with_mdts(
            zns_dev->dev_fd, zns_dev->dev_nsid, log_table_map[fst_cog_address],
            t_nlb, buf_t, (t_nlb * my_dev->lba_size_bytes),
            my_dev->lba_size_bytes, zns_dev->mdts, true);

        t_nlb = 1;
        cur_address = next_address;
        fst_cog_address = cur_address;
      }
    }

    return ret;
  }

  // error checking if read goes beyond defined log zone
  if (slba + nlb > zns_dev->log_zones * zns_dev->num_bpz) {
    printf("Error: reading is going beyond the log zones");
    return -1;
  }

  // reading using given starting slba
  ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba,
                                    nlb, buffer, size, my_dev->lba_size_bytes,
                                    zns_dev->mdts, true);
  return ret;
}

// func notifies the gc thread if zones need clearing, updates the wlba
// performs write on a circular log zone
int ss_write_to_log_zone(user_zns_device *my_dev, uint64_t address,
                         void *buffer, int size) {
  int ret = -ENOSYS, free_log_lb, elba, nlb;

  struct zns_dev_params *zns_dev = (struct zns_dev_params *)my_dev->_private;

  elba = zns_dev->log_zones * zns_dev->num_bpz;  // ending lba of log zone
  free_log_lb = ss_get_logzone_free_lb(zns_dev->wlba, zns_dev->tail_lba, elba);

  // clear log lbs until the minimum requirement for log zones is hit
  while (free_log_lb <= zns_dev->gc_wmark_lb) {
    clear_lz1 = true;
    cv.notify_one();  // notify gc to run, wait until reset
    {
      std::unique_lock<std::mutex> lk(gc_mutex);
      cv.wait(lk, [] { return lz1_cleared; });
    }
    lz1_cleared = false;

    free_log_lb =
        ss_get_logzone_free_lb(zns_dev->wlba, zns_dev->tail_lba, elba);
  }

  log_table_mutex.lock();

  // when log zone is not sequential
  if (zns_dev->wlba > zns_dev->tail_lba) {
    int rem_size;
    int slba = zns_dev->wlba;
    int size_bytes_slba_elba = (elba - slba) * (int)my_dev->lba_size_bytes;

    if (size <= size_bytes_slba_elba) {
      nlb = size / my_dev->lba_size_bytes;
      ret = ss_nvme_device_io_with_mdts(
          zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb, buffer, size,
          my_dev->lba_size_bytes, zns_dev->mdts, false);
      ss_update_log_table(nlb, address, slba, (uint32_t)my_dev->lba_size_bytes,
                          false);

      zns_dev->wlba += nlb;

      if ((int)zns_dev->wlba == elba) zns_dev->wlba = 0x00;

      log_table_mutex.unlock();
      return ret;

    } else {
      // circular log zone insert
      nlb = elba - slba;
      ret = ss_nvme_device_io_with_mdts(
          zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb, buffer, size,
          my_dev->lba_size_bytes, zns_dev->mdts, false);
      ss_update_log_table(nlb, address, slba, (uint32_t)my_dev->lba_size_bytes,
                          false);

      // pointing to remainder of buffer
      uint8_t *rem_buffer = ((uint8_t *)buffer) + size_bytes_slba_elba;
      rem_size = size - size_bytes_slba_elba;
      uint64_t rem_address_st = address + (uint32_t)rem_size;

      // write remaining buffer to log zone
      nlb = (rem_size) / (uint32_t)my_dev->lba_size_bytes;
      ret = ss_nvme_device_io_with_mdts(
          zns_dev->dev_fd, zns_dev->dev_nsid, 0x00, nlb, rem_buffer, rem_size,
          my_dev->lba_size_bytes, zns_dev->mdts, false);
      ss_update_log_table(nlb, rem_address_st, 0x00,
                          (uint32_t)my_dev->lba_size_bytes, false);
      zns_dev->wlba = nlb;

      log_table_mutex.unlock();
      return ret;
    }
  } else {
    // write normally as log zone is currently sequential
    nlb = size / my_dev->lba_size_bytes;
    ret = ss_nvme_device_io_with_mdts(
        zns_dev->dev_fd, zns_dev->dev_nsid, zns_dev->wlba, nlb, buffer, size,
        my_dev->lba_size_bytes, zns_dev->mdts, false);
    ss_update_log_table(nlb, address, zns_dev->wlba, my_dev->lba_size_bytes,
                        false);
    zns_dev->wlba += nlb;

    log_table_mutex.unlock();
    return ret;
  }
}

// read from data_zone using virtual address
int ss_read_from_data_zone(struct user_zns_device *my_dev, uint64_t address,
                           void *buffer, int size) {
  int ret, nlb, slba;
  struct zns_dev_params *zns_dev;

  zns_dev = (struct zns_dev_params *)my_dev->_private;

  nlb = size / my_dev->lba_size_bytes;
  slba = ss_get_ad_dz_lba(address, my_dev->tparams.zns_zone_capacity,
                          my_dev->lba_size_bytes, zns_dev->log_zones);
  ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba,
                                    nlb, buffer, size, my_dev->lba_size_bytes,
                                    zns_dev->mdts, true);

  return ret;
}

// write to one full data zone
int ss_write_to_data_zone(struct user_zns_device *my_dev, uint64_t address,
                          void *buffer, int size) {
  // check if size is in line with data zone size

  int ret, nlb, slba;
  struct zns_dev_params *zns_dev;

  zns_dev = (struct zns_dev_params *)my_dev->_private;

  if (size != static_cast<int>(my_dev->tparams.zns_zone_capacity)) {
    printf("Error: only zone size writes allowed in data zone \n");
    return -1;
  }

  nlb = size / my_dev->lba_size_bytes;
  slba = ss_get_dz_slba(address, my_dev->tparams.zns_zone_capacity,
                        my_dev->lba_size_bytes, zns_dev->log_zones);
  ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba,
                                    nlb, buffer, size, my_dev->lba_size_bytes,
                                    zns_dev->mdts, true);

  return ret;
}

// add one buffers blocks onto another at given offsets
void stack_buff_at_offsets(std::vector<uint8_t> buff,
                           std::vector<uint8_t> &buff_dest,
                           std::vector<int> offset_list, int lba_size) {
  int offset;
  if (buff.size() != buff_dest.size()) {
    printf("Errors: the buffers are not of the same size");
  }

  for (uint32_t i = 0; i < offset_list.size(); i++) {
    offset = offset_list[i];

    auto st = buff.begin() + (offset * lba_size);
    auto end = st + lba_size;

    auto cp_st = buff_dest.begin() + (offset * lba_size);

    std::copy(st, end, cp_st);
  }
}

// stack a dz buffer with a log zone buffer (can contain multiple addresses)
void stack_buff_with_log_zone(std::vector<char> log_zone_buffer,
                              std::vector<char> &data_zone_buffer,
                              std::vector<long long int> log_table_c,
                              uint64_t address, int slba, int nlb,
                              int zone_size_in_bytes, int lba_size,
                              int num_of_log_zones) {
  int end_address = static_cast<int>(address + zone_size_in_bytes);
  int block_offset;

  for (int i = slba; i < slba + nlb; i++) {
    if (log_table_c[i] >= static_cast<int>(address) &&
        log_table_c[i] < end_address) {
      int dzlba = ss_get_ad_dz_lba(log_table_c[i], zone_size_in_bytes, lba_size,
                                   num_of_log_zones);
      int dzslba = ss_get_dz_slba(log_table_c[i], zone_size_in_bytes, lba_size,
                                  num_of_log_zones);

      block_offset = dzlba - dzslba;

      auto st = log_zone_buffer.begin() + ((i - slba) * lba_size);
      auto end = st + lba_size;

      auto dest = data_zone_buffer.begin() + (block_offset * lba_size);
      std::copy(st, end, dest);
    }
  }
}

// creates a log table mapping for an address space using log table
void create_log_table_mapping_for_va(
    std::unordered_map<uint64_t, uint64_t> &log_table_map, uint64_t address,
    int size, int wlba, int tail_lba, int elba) {
  int end_ad = address + (uint64_t)size;

  // when log table is circular
  if (wlba < tail_lba && tail_lba != elba) {
    for (uint64_t i = tail_lba; i < log_table.size(); i++) {
      if (log_table[i] >= static_cast<int>(address) && log_table[i] < end_ad) {
        if (log_table_map.count(log_table[i]) > 0)
          log_table_map[log_table[i]] = i;
        else
          log_table_map.insert(std::make_pair(log_table[i], i));
      }
    }
    for (int i = 0; i < wlba; i++) {
      if (log_table[i] >= static_cast<int>(address) && log_table[i] < end_ad) {
        if (log_table_map.count(log_table[i]) > 0)
          log_table_map[log_table[i]] = i;
        else
          log_table_map.insert(std::make_pair(log_table[i], i));
      }
    }

    // when log table is semi circular
  } else if (wlba > tail_lba) {
    for (int i = tail_lba; i < wlba; i++) {
      if (log_table[i] >= static_cast<int>(address) && log_table[i] < end_ad) {
        if (log_table_map.count(log_table[i]) > 0)
          log_table_map[log_table[i]] = i;
        else
          log_table_map.insert(std::make_pair(log_table[i], i));
      }
    }

    // when log table is sequental
  } else {
    for (int i = 0; i < wlba; i++) {
      if (log_table[i] >= static_cast<int>(address) && log_table[i] < end_ad) {
        if (log_table_map.count(log_table[i]) > 0)
          log_table_map[log_table[i]] = i;
        else
          log_table_map.insert(std::make_pair(log_table[i], i));
      }
    }
  }
}

void create_offset_map_log_data(
    std::unordered_map<uint64_t, uint64_t> log_table_map,
    std::vector<int> &offset_map, int zone_size_in_bytes, int lba_size,
    int num_of_log_zones, uint64_t address) {
  int buf_block_offset, buf_slba, lba;

  buf_slba =
      ss_get_ad_dz_lba(address, zone_size_in_bytes, lba_size, num_of_log_zones);

  for (auto &pair : log_table_map) {
    lba = ss_get_ad_dz_lba(pair.first, zone_size_in_bytes, lba_size,
                           num_of_log_zones);
    buf_block_offset = lba - buf_slba;
    offset_map.push_back(buf_block_offset);
  }
}

// create a list of which data zones to read
void create_dz_read_list(std::vector<bool> &dz_read,
                         std::vector<uint64_t> log_table_c, int slba, int nlb,
                         int zone_size_in_bytes, int num_of_log_zones) {
  for (int i = slba; i < slba + nlb; i++) {
    dz_read[ss_get_dz(log_table_c[slba], zone_size_in_bytes,
                      num_of_log_zones)] = true;
  }
}

int ss_write_reset_lz(struct user_zns_device *my_dev, int lzslba,
                      void *log_zone_buffer) {
  int nlb, zone_size;
  struct zns_dev_params *zns_dev;

  nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;
  zone_size = my_dev->tparams.zns_zone_capacity;
  zns_dev = (struct zns_dev_params *)(my_dev->_private);

  // reset log zone, delete entries in log_map
  ss_update_log_table(nlb, 0, lzslba, my_dev->lba_size_bytes, true);

  int ret = ss_nvme_device_io_with_mdts(
      zns_dev->dev_fd, zns_dev->dev_nsid, lzslba, nlb, log_zone_buffer,
      zone_size, my_dev->lba_size_bytes, zns_dev->mdts, true);
  ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, lzslba, false,
                           NVME_ZNS_ZSA_RESET, 0,
                           nullptr);  // reset zone

  // update tail pointer
  if ((int)zns_dev->tail_lba == zns_dev->log_zones * zns_dev->num_bpz)
    zns_dev->tail_lba = 0x00 + zns_dev->num_bpz;
  else
    zns_dev->tail_lba = zns_dev->tail_lba + zns_dev->num_bpz;

  if ((int)zns_dev->target_lzslba ==
      (zns_dev->log_zones - 1) * zns_dev->num_bpz)
    zns_dev->target_lzslba = 0x00;
  else
    zns_dev->target_lzslba = lzslba + zns_dev->num_bpz;

  return ret;
}

// create a table of which data zones to update using the log buffer
void create_dz_update_table(std::vector<bool> &dz_update_table,
                            std::vector<long long int> log_table_c, int lzslba,
                            int nlb, int zone_size_in_bytes, int log_zones) {
  for (int i = lzslba; i < lzslba + nlb; i++) {
    int dz_to_upd = ss_get_dz(log_table_c[i], zone_size_in_bytes, log_zones);
    dz_update_table[dz_to_upd] = true;
  }
}

// write a log zone buffer to data zone
int ss_write_lz_buf_dz(struct user_zns_device *my_dev, int lzslba,
                       std::vector<long long int> log_table_c,
                       std::vector<char> log_zone_buffer) {
  int nlb, zone_size, ret;
  struct zns_dev_params *zns_dev;
  std::vector<char> data_zone_buffer;
  std::vector<bool> dz_update_table;

  nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;
  zns_dev = (struct zns_dev_params *)(my_dev->_private);
  zone_size = my_dev->tparams.zns_zone_capacity;
  data_zone_buffer = std::vector<char>(zone_size);
  dz_update_table = std::vector<bool>(
      zns_dev->log_zones + my_dev->capacity_bytes / zone_size, false);

  create_dz_update_table(dz_update_table, log_table_c, lzslba, nlb, zone_size,
                         zns_dev->log_zones);

  // iterating though zones we need to read
  for (uint32_t i = zns_dev->log_zones; i < dz_update_table.size(); i++) {
    if (dz_update_table[i]) {
      // read from data zone if data exists
      if (data_zone_table[i]) {
        ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, i * nlb,
                                    nlb, data_zone_buffer.data(), zone_size,
                                    my_dev->lba_size_bytes, zns_dev->mdts,
                                    true);
      }

      // add log zone entries to the data zone buffer
      uint64_t virtual_address_dz = (i - zns_dev->log_zones) * zone_size;
      stack_buff_with_log_zone(log_zone_buffer, data_zone_buffer, log_table_c,
                               virtual_address_dz, lzslba, nlb,
                               my_dev->tparams.zns_zone_capacity,
                               my_dev->lba_size_bytes, zns_dev->log_zones);

      // reset the datazone and write fresh data to it
      ret =
          nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, (__u64)i * nlb,
                             false, NVME_ZNS_ZSA_RESET, 0, nullptr);
      ret = ss_nvme_device_io_with_mdts(
          zns_dev->dev_fd, zns_dev->dev_nsid, i * nlb, nlb,
          data_zone_buffer.data(), my_dev->tparams.zns_zone_capacity,
          my_dev->lba_size_bytes, zns_dev->mdts, false);

      data_zone_table[i] = true;  // data_zone now has entries
    }
  }

  return ret;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev) {
  int ret = -ENOSYS;
  // this is to supress gcc warnings, remove it when you complete this
  // function

  // shutting down gc
  {
    std::lock_guard<std::mutex> lk(gc_mutex);
    gc_shutdown = true;
  }

  clear_lz1 = true;
  cv.notify_one();  // run gc one more time and exit

  gc_thread.join();
  free(my_dev->_private);
  free(my_dev);
  // push metadata onto the device
  return ret;
}

// create a log table copy
void create_log_table_copy(std::vector<long long int> &log_table_c, int lzslba,
                           int nlb) {
  log_table_c = std::vector<long long int>(log_table.size());
  for (int i = lzslba; i < lzslba + nlb; i++) {
    log_table_c[i] = log_table[i];
  }
}

void gc_main(struct user_zns_device *my_dev) {
  struct zns_dev_params *zns_dev;
  int nr_dzones, c_target_lzslba, nlb;

  // write error checking code

  zns_dev = (struct zns_dev_params *)my_dev->_private;
  nr_dzones = my_dev->capacity_bytes / my_dev->tparams.zns_zone_capacity;
  nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;

  while (true && !gc_shutdown) {
    std::unique_lock<std::mutex> lk(gc_mutex);
    cv.wait(lk, [] { return clear_lz1; });

    std::vector<long long int> log_table_c;
    std::vector<bool> dz_read(zns_dev->log_zones + nr_dzones, false);
    std::vector<char> log_zone_buffer(my_dev->tparams.zns_zone_capacity);

    log_table_mutex.lock();
    create_log_table_copy(log_table_c, zns_dev->target_lzslba, nlb);
    log_table_mutex.unlock();

    ss_write_reset_lz(my_dev, zns_dev->target_lzslba, log_zone_buffer.data());

    if (zns_dev->target_lzslba == 0x00) {
      c_target_lzslba = (zns_dev->log_zones - 1) * zns_dev->num_bpz;
    } else {
      c_target_lzslba = zns_dev->target_lzslba - zns_dev->num_bpz;
    }

    clear_lz1 = false;
    lz1_cleared = true;

    ss_write_lz_buf_dz(my_dev, c_target_lzslba, log_table_c, log_zone_buffer);

    lk.unlock();
    cv.notify_one();  // notify write thread to start writing after reset
   }
}

int init_ss_zns_device(struct zdev_init_params *params,
                       struct user_zns_device **my_dev) {
  int ret = -ENOSYS;
  // this is to supress gcc warnings, remove it when you complete this
  // function
  struct nvme_id_ns ns {};
  nvme_zns_id_ns zns_ns;
  *my_dev = (struct user_zns_device *)malloc(sizeof(struct user_zns_device));
  struct nvme_zone_report zns_report;
  struct zns_dev_params *zns_dev =
      (struct zns_dev_params *)malloc(sizeof(struct zns_dev_params));

  // Open device and setup zns_dev_params
  zns_dev->dev_fd = nvme_open(params->name);
  ret = nvme_get_nsid(zns_dev->dev_fd, &zns_dev->dev_nsid);
  zns_dev->wlba = 0x00;
  zns_dev->target_lzslba = 0x00;
  zns_dev->log_zones = params->log_zones;

  // getting mdts
  int mdts = get_mdts_size(2, params->name, zns_dev->dev_fd);
  zns_dev->mdts = mdts;

  // Reset device
  ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, (__u64)0x00,
                           true, NVME_ZNS_ZSA_RESET, 0, nullptr);

  // Get logical block size
  ret = nvme_identify_ns(zns_dev->dev_fd, zns_dev->dev_nsid, &ns);
  (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[(ns.flbas & 0xf)].ds;

  // getting total zones in the namespace
  ret = nvme_zns_mgmt_recv(zns_dev->dev_fd, (uint32_t)zns_dev->dev_nsid, 0,
                           NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL,
                           0, sizeof(zns_report), (void *)&zns_report);
  (*my_dev)->tparams.zns_num_zones =
      le64_to_cpu(zns_report.nr_zones) - params->log_zones;

  // getting number of blocks per zone
  ret = nvme_zns_identify_ns(zns_dev->dev_fd, (uint32_t)zns_dev->dev_nsid,
                             &zns_ns);
  zns_dev->num_bpz = le64_to_cpu(zns_ns.lbafe[(ns.flbas & 0xf)].zsze);
  (*my_dev)->tparams.zns_zone_capacity =
      zns_dev->num_bpz *
      (*my_dev)->tparams.zns_lba_size;  // number of bytes in a zone
  zns_dev->gc_wmark_lb =
      params->gc_wmark * zns_dev->num_bpz;  // gc_wmark logical block address
  zns_dev->tail_lba =
      params->log_zones * zns_dev->num_bpz;  // tail lba set to end of log zone

  (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
  (*my_dev)->capacity_bytes =
      (*my_dev)->tparams.zns_zone_capacity *
      (*my_dev)->tparams.zns_num_zones;  // writable size of device in bytes

  (*my_dev)->_private = (void *)zns_dev;
  int gc_table_size = (*my_dev)->tparams.zns_num_zones + zns_dev->log_zones;

  data_zone_table = std::vector<bool>(gc_table_size);
  log_table =
      std::vector<long long int>(zns_dev->log_zones * zns_dev->num_bpz, -1);

  // Start the GC thread and init the conditional variables
  lz1_cleared = false;
  clear_lz1 = false;
  gc_shutdown = false;
  gc_thread = std::thread(gc_main, *my_dev);

  return ret;
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address,
                     void *buffer, uint32_t size) {
  int ret = -ENOSYS, dz, elba;
  struct zns_dev_params *zns_dev = (struct zns_dev_params *)my_dev->_private;
  std::vector<uint8_t> buf_vec(size);
  std::vector<uint8_t> buf_vec_log_zone(size);
  std::unordered_map<uint64_t, uint64_t> log_table_map;
  std::vector<int> offset_map;

  log_table_mutex.lock();
  dz =
      ss_get_dz(address, my_dev->tparams.zns_zone_capacity, zns_dev->log_zones);

  // read from data zone if entry exists
  if (data_zone_table[dz]) {
    ret = ss_read_from_data_zone(my_dev, address, buf_vec.data(), size);
  }

  // read from log zone (using virtual address)
  elba = zns_dev->log_zones * zns_dev->num_bpz;
  create_log_table_mapping_for_va(log_table_map, address, size, zns_dev->wlba,
                                  zns_dev->tail_lba, elba);
  ret = ss_read_from_log_zone(my_dev, address, 0, buf_vec_log_zone.data(), size,
                              0, true, log_table_map);

  // apply log table buffer onto data zone buffer
  create_offset_map_log_data(
      log_table_map, offset_map, my_dev->tparams.zns_zone_capacity,
      my_dev->lba_size_bytes, zns_dev->log_zones, address);
  stack_buff_at_offsets(buf_vec_log_zone, buf_vec, offset_map,
                        my_dev->lba_size_bytes);

  memcpy(buffer, buf_vec.data(), size);
  log_table_mutex.unlock();
  return ret;
}

int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address,
                      void *buffer, uint32_t size) {
  int ret = -ENOSYS;

  // write to end of log zone
  ret = ss_write_to_log_zone(my_dev, address, buffer, size);
  return ret;
}
}
