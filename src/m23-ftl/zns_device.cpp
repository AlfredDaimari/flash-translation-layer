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


#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <libnvme.h>
#include <cstdlib>
#include <nvme/ioctl.h>
#include <nvme/tree.h>
#include <nvme/types.h>
#include <nvme/util.h>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <mutex>

#include "zns_device.h"
#include "../common/unused.h"



std::unordered_map<uint64_t, uint64_t> log_table = {};
std::unordered_map<uint64_t, uint64_t> lb_vb_table = {};
std::vector<bool> gc_table; // gc_table: len = num data zones
std::vector<bool> dz_write_table;

std::thread gc_thread;
std::condition_variable cv;
std::mutex log_table_mutex;
std::mutex gc_mutex;
bool lz1_cleared;
bool clear_lz1;
bool gc_shutdown;

extern "C" {

int ss_get_mdts(const char *dev_name, int dev_fd){

        char path[512];
        void *bar;
        nvme_ns_t n = NULL;

        //taken from nvme_cli
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

       //printf("Path is %s\n", path);
       int fd = open(path, O_RDONLY);
	   if (fd < 0) {
		 printf("%s did not find a pci resource, open failed \n",
				dev_name);
       }

       nvme_id_ctrl zns_id_ctrl;
       nvme_identify_ctrl(dev_fd, &zns_id_ctrl);  


        bar = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, fd, 0);
        close(fd);
        uint64_t cap = nvme_mmio_read64(bar);
        //printf("The cap is %lu\n", cap);
        __u32 mpsmin = ((__u8 *)&cap)[6] & 0x0f;
        mpsmin = (1 << (12 + mpsmin));
        //printf("The mpsmin is %u\n", mpsmin);
        int mdts = mpsmin * (1 << (zns_id_ctrl.mdts - 1));
        //printf("The mdts is %i\n", mdts);
        munmap(bar, getpagesize());
        return mdts;

}

void update_lba(uint64_t &write_lba, const uint32_t lba_size, const int count){
    UNUSED(lba_size); 
    write_lba += count;
    
}

int ss_get_dz_num(uint64_t address, int zone_size, int log_offset){

        return (address / zone_size) + log_offset;
}

int ss_get_adr_dz_slba(uint64_t address, int zone_bytes, int lba_size,int log_offset){
        int dz_slba_0based = address / lba_size;
        int log_lba_offset = (zone_bytes * log_offset) / lba_size;
        return log_lba_offset + dz_slba_0based;
}

int ss_nvme_device_read(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size) {
int ret = -ENOSYS;
// this is to supress gcc warnings, remove it when you complete this function    
ret = nvme_read(fd, nsid, slba, numbers - 1, 0, 0, 0, 0, 0, buf_size, buffer, 0, nullptr);

return ret;
}

int ss_nvme_device_write(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size) {
        int ret = -ENOSYS;
        // this is to supress gcc warnings, remove it when you complete this function   
        ret = nvme_write(fd, nsid, slba, numbers - 1, 0, 0, 0, 0, 0, 0, buf_size, buffer, 0, nullptr);
        if (ret != 0){
                printf("the error is %i, number is %i, %s\n", ret, numbers,nvme_status_to_string(ret,false));
        }
        return ret;
}

int ss_get_logzone_free_blocks(int wlba, int tail_lba, int end_lba){
        if (wlba > tail_lba){
                return tail_lba + ( end_lba - wlba);
        } 
                return tail_lba - wlba; 
}

void ss_update_log_table(int nlb, uint64_t &address, int slba, int lba_size){
// adding mappings to the log table

// this function updates the address
    
    for (int i = 0; i < nlb; i++){
            if (log_table.count(address) > 0){
                    log_table[address] = slba;
                    lb_vb_table[slba] = address;
                    } else {
                    log_table.insert(std::make_pair(address, slba));
                    lb_vb_table.insert(std::make_pair(slba, address));
            }
            
            //update both wlba and address by logical block size
            slba += 1;
            // if wlba == threshold, if threshold reached, activate semaphore
            address += lba_size;
    }  
}

int ss_nvme_device_io_with_mdts(user_zns_device *my_dev,int fd, uint32_t nsid, uint64_t slba, uint64_t address, void *buffer, uint64_t buf_size,
                                uint64_t lba_size, uint64_t mdts_size, bool read, bool log_zone_write){ 
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    int num_ops, size, end_lba, nlb;
    struct zns_dev_params * zns_dev = (struct zns_dev_params *) my_dev->_private;

    end_lba = zns_dev->num_bpz * zns_dev->log_zones;
    if (mdts_size < buf_size){
        num_ops = buf_size / mdts_size;
        size = mdts_size;
    } else {
            num_ops = 1;
            size = buf_size;
    }
    uint8_t * buf = (uint8_t *) buffer;
    nlb = size / lba_size;
    
    if (log_zone_write)
            log_table_mutex.lock();

    if (read){
            //printf("starting lba is %i, total lba is %i\n", slba, numbers);
            for (int i = 0; i < num_ops; i++){
                    ret = ss_nvme_device_read(fd, nsid, slba, nlb, buf, size);
                    buf += size;
                    update_lba(slba, lba_size, nlb);
            }
    } else {
            for (int i = 0; i < num_ops; i++){
                    // write to log zone needs log_table_updation
                    if (log_zone_write){
                           if ((slba + nlb) > end_lba){
                                // write from wlba to tail_lba, also update log wlba
                                int t_nlb = end_lba - slba;
                                ret = ss_nvme_device_write(fd, nsid, slba, t_nlb, buf, t_nlb * my_dev->lba_size_bytes);
                                ss_update_log_table(t_nlb, address, slba, my_dev->lba_size_bytes);

                                // write from 0x00 to size
                                t_nlb = (slba + nlb) - end_lba;
                                slba = 0x00; 
                                ret = ss_nvme_device_write(fd, nsid, slba, t_nlb, buf, t_nlb * my_dev->lba_size_bytes);
                                ss_update_log_table(t_nlb, address, slba, my_dev->lba_size_bytes);
                                update_lba(slba, lba_size, t_nlb);
                                zns_dev->wlba = slba;

                           } else if((slba + nlb) == end_lba) {
                                   ret = ss_nvme_device_write(fd, nsid, slba, nlb, buf, size);
                                   ss_update_log_table(nlb, address, slba, my_dev->lba_size_bytes);
                                   slba = 0x00;
                                   zns_dev->wlba = slba;
                           } else {
                                ret = ss_nvme_device_write(fd, nsid, slba, nlb, buf, size);
                                ss_update_log_table(nlb, address, slba, my_dev->lba_size_bytes);
                                update_lba(slba, lba_size, nlb);
                                zns_dev->wlba = slba;
                           }
                    }
                    // write to data zone
                    else {
                        ret = ss_nvme_device_write(fd, nsid, slba, nlb, buf, size);
                        update_lba(slba, lba_size, nlb);
                    }
                    buf += size;
        }
    }

    if (log_zone_write)
            log_table_mutex.unlock();

    return ret;
}

int ss_read_lzdz(struct user_zns_device *my_dev, uint64_t address, void *buffer, int size){
        int nlb_mdts, dz_slba, slba, endlba, dz_sba_0b;
        bool read_eval;
        void * log_mdts_buffer;
        struct zns_dev_params * zns_dev;
 
        read_eval = true;
        zns_dev = (struct zns_dev_params *) my_dev->_private;
        dz_slba = ss_get_adr_dz_slba(address, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->log_zones); // starting block address of data zone to read from
        dz_sba_0b = address / my_dev->lba_size_bytes; // dz_slba without log offset
        nlb_mdts = zns_dev->mdts / my_dev->lba_size_bytes;
        log_mdts_buffer = malloc(zns_dev->mdts); 
        
        // read data from data zones (can be minimized using gc_table)
        int ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, dz_slba, 0, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);
        
        log_table_mutex.lock();

        if (zns_dev->tail_lba < zns_dev->wlba){
                slba = zns_dev->tail_lba;
                endlba = zns_dev->wlba;
        } else {
                if (zns_dev->tail_lba != zns_dev->log_zones * zns_dev->num_bpz){
                        slba = zns_dev->tail_lba;
                        endlba = zns_dev->log_zones * zns_dev->num_bpz;
                } else {
                        slba = 0x00;
                        endlba = zns_dev->wlba;
                }
        }

        read_loop:
        while (slba < endlba){

                // read mtds blocks if slba exists
                int slba_va = lb_vb_table[slba];
                if (slba_va >= address && slba_va < (address + size)){

                        ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, slba, 0, log_mdts_buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);
                        int temp_slba = slba;
                        int temp_endlba = slba + nlb_mdts;

                        uint8_t * t_lz_buf = (uint8_t *) log_mdts_buffer;
                        uint8_t * t_dz_buf = (uint8_t *) buffer;

                        while (temp_slba < temp_endlba){

                                // there is an entry in the read mdts buffer, apply the lba on the return buffer
                                if (lb_vb_table.count(temp_slba) > 0){
                                        int vaddress = lb_vb_table[temp_slba];

                                        int dz_block_offset = ( vaddress / my_dev->lba_size_bytes) - dz_sba_0b;
                                        int lz_block_offset = temp_slba - slba;

                                        uint8_t * dz_lba_copy_ad = t_dz_buf + (dz_block_offset * my_dev->lba_size_bytes);
                                        uint8_t * lz_lba_copy_ad = t_lz_buf + (lz_block_offset * my_dev->lba_size_bytes);
                                        mempcpy(dz_lba_copy_ad, lz_lba_copy_ad, my_dev->lba_size_bytes);

                                }
                                temp_slba += 1;
                        }
                        slba += nlb_mdts;
                } else {
                        slba += 1; 
                }
        }
 
        if (zns_dev->tail_lba > zns_dev->wlba && read_eval && zns_dev->tail_lba != endlba){
                slba = 0x00;
                endlba = zns_dev->wlba;
                read_eval = false;
                goto read_loop;
        }
        
        log_table_mutex.unlock();
        
        free(log_mdts_buffer);
        return ret;
}

int ss_write_reset_lz(struct user_zns_device *my_dev, int lzslba,std::vector<bool> &dz_read, void ** log_zone_buffer){
        int nlb, zone_size; 
        struct zns_dev_params * zns_dev;

        nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;
        zone_size = my_dev->tparams.zns_zone_capacity;
        *log_zone_buffer = malloc(zone_size);
        zns_dev = (struct zns_dev_params *) (my_dev->_private);
       
        // reset log zone, delete entries         
        log_table_mutex.lock();
        
        int ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, lzslba, 0, *log_zone_buffer, zone_size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);        
        for (int i = lzslba; i < lzslba+nlb; i++){
                int vb_ad = lb_vb_table[i];
                int t_dz_num = ss_get_dz_num(lb_vb_table[i], my_dev->tparams.zns_zone_capacity, zns_dev->log_zones);
                dz_read[t_dz_num] = true;
                lb_vb_table.erase(i);
                log_table.erase(vb_ad);
        }

        log_table_mutex.unlock();

        ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, lzslba, false, NVME_ZNS_ZSA_RESET, 0, nullptr); // reset zone
        return ret;
}

int ss_write_lz_buf_dz(struct user_zns_device *my_dev, int lzslba, std::unordered_map<uint64_t, uint64_t> log_table_c, std::vector<bool>dz_read, void *log_zone_buffer){
        int nlb, zone_size,ret;
        void * data_zone_buffer;
        struct zns_dev_params * zns_dev;
        
        nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;
        zns_dev = (struct zns_dev_params *) (my_dev->_private);
        zone_size = my_dev->tparams.zns_zone_capacity;
       
        data_zone_buffer = malloc(zone_size);
        
        // iterating though zones we need to read
        for (int i = zns_dev->log_zones; i < dz_read.size(); i++){
                if (dz_read[i]){
                        gc_table[i] = true;
                        int dslba = i * nlb;  
                        ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, dslba, 0, data_zone_buffer, zone_size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);
                        // error printing for ret
                        uint8_t * t_dz_buf = (uint8_t *) data_zone_buffer;
                        uint8_t * t_lz_buf = (uint8_t *) log_zone_buffer;

                        int vb_of_zone = (i - zns_dev->log_zones) * zone_size; // the starting virtual address of zone 

                        // get blocks in the log zone to be cleared that belong to a data zones's virtual address range
                        for (int j = i * vb_of_zone; j < vb_of_zone + zone_size; j+= my_dev->lba_size_bytes){
                                
                                if (log_table_c.count(j) > 0 && log_table_c[j] < (lzslba + nlb)){ 
                                        mempcpy(t_dz_buf, t_lz_buf, my_dev->lba_size_bytes);
                                }
                                
                                t_dz_buf += my_dev->lba_size_bytes;
                                t_lz_buf += my_dev->lba_size_bytes;
                        }

                        // reset the datazone and write fresh data to it
                        ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, (__u64) i*nlb, false, NVME_ZNS_ZSA_RESET, 0, nullptr);
                        ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, i * nlb, 0, data_zone_buffer, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->mdts, false, false);

                }
        }

        free(data_zone_buffer);
        return ret;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev) {    
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function
    
    //shutting down gc
    {
            std::lock_guard<std::mutex> lk(gc_mutex);
            gc_shutdown = true;
    }

    clear_lz1 = true;
    cv.notify_one();    // run gc one more time and exit

    gc_thread.join();
    free(my_dev->_private);
    free(my_dev);
    // push metadata onto the device
    return ret;
}

void gc_main(struct user_zns_device *my_dev) {
    
    struct zns_dev_params * zns_dev;
    int ret, nr_dzones;
    __u64 end_lba;

    zns_dev = (struct zns_dev_params *) my_dev->_private;
    ret = -1;
    nr_dzones = my_dev->capacity_bytes / my_dev->lba_size_bytes;
    end_lba = zns_dev->log_zones * zns_dev->num_bpz; // lba where log zone ends

    
    while (true && !gc_shutdown) {

        std::unique_lock<std::mutex> lk(gc_mutex);
        cv.wait(lk, []{return clear_lz1;});
   
        std::unordered_map<uint64_t, uint64_t> log_table_c;
        std::vector<bool> dz_read(zns_dev->log_zones + nr_dzones ,false);
        void * log_zone_buffer;

        log_table_c = log_table; 
        ss_write_reset_lz(my_dev,zns_dev->target_lzslba, dz_read, &log_zone_buffer);
        
        // tail lba update on reset
        if (zns_dev->tail_lba == end_lba){
                zns_dev->tail_lba = 0x00 + zns_dev->num_bpz;
        } else {
                zns_dev->tail_lba += zns_dev->num_bpz;
        }

        if (zns_dev->target_lzslba + zns_dev->num_bpz == end_lba){ // checking if last zone was the one cleared
                zns_dev->target_lzslba = 0x00;
        } else {
                zns_dev->target_lzslba += zns_dev->num_bpz; // update target_lzslba to start of next block
        }

        clear_lz1 = false;
        lz1_cleared = true;
        
        lk.unlock(); 
        cv.notify_one(); // notify write thread to start writing after reset

        ss_write_lz_buf_dz(my_dev, zns_dev->target_lzslba, log_table_c, dz_read, log_zone_buffer);

        free(log_zone_buffer); 
        }

}

int init_ss_zns_device(struct zdev_init_params *params, struct user_zns_device **my_dev){    
    
    int ret = -ENOSYS;    
    // this is to supress gcc warnings, remove it when you complete this function  
    struct nvme_id_ns ns{};
    nvme_zns_id_ns zns_ns;
    *my_dev = (struct user_zns_device *) malloc(sizeof(struct user_zns_device));
    struct nvme_zone_report zns_report;
    struct zns_dev_params * zns_dev = (struct zns_dev_params *)malloc(sizeof(struct zns_dev_params));
   
    // Open device and setup zns_dev_params
    zns_dev->dev_fd = nvme_open(params->name);
    ret = nvme_get_nsid(zns_dev->dev_fd, &zns_dev->dev_nsid);
    zns_dev->wlba = 0x00;
    zns_dev->target_lzslba = 0x00;
    zns_dev->log_zones = params->log_zones;


    // getting mdts 
    int mdts = ss_get_mdts(params->name, zns_dev->dev_fd);
    zns_dev->mdts = mdts;
   
    // Reset device
    ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid,(__u64)0x00, true, NVME_ZNS_ZSA_RESET, 0, nullptr);
       
    // Get logical block size
    ret = nvme_identify_ns(zns_dev->dev_fd, zns_dev->dev_nsid, &ns);
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[(ns.flbas & 0xf)].ds;
   
    // getting total zones in the namespace
    ret = nvme_zns_mgmt_recv(zns_dev->dev_fd, (uint32_t) zns_dev->dev_nsid,0, NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL,0, sizeof(zns_report), (void *) &zns_report);
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zns_report.nr_zones) - params->log_zones;

    // getting number of blocks per zone
    ret = nvme_zns_identify_ns(zns_dev->dev_fd, (uint32_t) zns_dev->dev_nsid, &zns_ns); 
    zns_dev->num_bpz = le64_to_cpu(zns_ns.lbafe[(ns.flbas & 0xf)].zsze);
    (*my_dev)->tparams.zns_zone_capacity = zns_dev->num_bpz * (*my_dev)->tparams.zns_lba_size; // number of bytes in a zone
    zns_dev->gc_wmark_lba = params->gc_wmark * zns_dev->num_bpz;    // gc_wmark logical block address
    zns_dev->tail_lba = params->log_zones * zns_dev->num_bpz; // tail lba set to end of log zone

    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    (*my_dev)->capacity_bytes = (*my_dev)->tparams.zns_zone_capacity * (*my_dev)->tparams.zns_num_zones; // writable size of device in bytes 

    (*my_dev)->_private = (void *) zns_dev;
    //printf("mdts block cap is %i, mdts is %i, mpsmin is %i", mdts/(*my_dev)->lba_size_bytes, mdts, mpsmin);
    // Resize gc_table based on num of dz ?
    int gc_table_size = (*my_dev)->tparams.zns_num_zones + zns_dev->log_zones;
    printf("gc_table_size: %i \n", gc_table_size);
    gc_table = std::vector<bool>(gc_table_size);   
    
    // Start the GC thread and init the conditional variables
    lz1_cleared = false;
    clear_lz1 = false;
    gc_shutdown = false;
    gc_thread = std::thread (gc_main,*my_dev);

 
    return ret;        
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int ret = -ENOSYS;    
    
    // Check if block aligned
    if (address % my_dev->lba_size_bytes != 0 || size % my_dev->lba_size_bytes != 0) {
        printf("ERROR: read request is not block aligned \n");
        return -EINVAL;
    }
 
    ret = ss_read_lzdz(my_dev,address, buffer, size);
    return ret;
}


int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int ret = -ENOSYS, gc_wmark_lba, lz_free_blocks, end_lba;   
    struct zns_dev_params * zns_dev; 

    zns_dev = (struct zns_dev_params *) (my_dev->_private);
    // Check if block aligned
    if (address % my_dev->lba_size_bytes != 0 || size % my_dev->lba_size_bytes != 0) {
        printf("ERROR: read request is not block aligned \n");
        return -EINVAL;
    } 
    
 
    gc_wmark_lba = zns_dev->gc_wmark_lba;     
    end_lba = zns_dev->num_bpz * zns_dev->log_zones;
    lz_free_blocks = ss_get_logzone_free_blocks(zns_dev->wlba, zns_dev->tail_lba, end_lba);

    while (gc_wmark_lba >= lz_free_blocks){
            // run gc when free_block < gc_wmark
            clear_lz1 = true;         
           
            cv.notify_one(); // notify gc to run, wait until reset
            {
                    std::unique_lock<std::mutex> lk(gc_mutex);
                    cv.wait(lk, []{return lz1_cleared;});
            }
            lz1_cleared = false;
            
            lz_free_blocks = ss_get_logzone_free_blocks(zns_dev->wlba, zns_dev->tail_lba, end_lba);
    }
  
    // write to device when there are enough free blocks
    ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, zns_dev->wlba, address, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts,false, true);
      
    return ret;
}

}

