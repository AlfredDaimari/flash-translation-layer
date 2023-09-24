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
std::vector<bool> gc_table = {}; // gc_table: len = num data zones
std::vector<bool> dz_write_table;
std::mutex log_table_mutex;
std::mutex gc_mutex;
std::thread gc_thread;

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
        int mdts = mpsmin * (1 << zns_id_ctrl.mdts);
        //printf("The mdts is %i\n", mdts);
        munmap(bar, getpagesize());
        return mdts;

}

void update_lba(uint64_t &write_lba, const uint32_t lba_size, const int count){
    UNUSED(lba_size); 
    write_lba += count;
    
}

int ss_get_dz_num(uint64_t address, int zone_bytes){
        return (address / zone_bytes) + 3;
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

int ss_nvme_device_io_with_mdts(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size,
                                uint64_t lba_size, uint64_t mdts_size, bool read){
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    int num_ops, size;

    if (mdts_size < buf_size){
        num_ops = buf_size / mdts_size;
        size = mdts_size;
    } else {
            num_ops = 1;
            size = buf_size;
    }
    uint8_t * buf = (uint8_t *) buffer;
    int n_nlb = size / lba_size; 

    if (read){
            //printf("starting lba is %i, total lba is %i\n", slba, numbers);
            for (int i = 0; i < num_ops; i++){
                    ret = ss_nvme_device_read(fd, nsid, slba, n_nlb, buf, size);
                    buf += size;
                    update_lba(slba, lba_size, n_nlb);
            }
    } else {
            for (int i = 0; i < num_ops; i++){ 
                    ret = ss_nvme_device_write(fd, nsid, slba, n_nlb, buf, size);
                    buf += size;
                    update_lba(slba, lba_size, n_nlb);
           }
    }

    return ret;
}

int ss_read_lzdz(struct user_zns_device *my_dev, uint64_t address, void *buffer, int size){
        int nlb_l, nlb_d, dzlba, slba, endlba, dz_sba;
        bool read_eval;
        void * log_mdts_buffer;
        struct zns_dev_params * zns_dev;
 
        read_eval = true;
        zns_dev = (struct zns_dev_params *) my_dev->_private;
        dzlba = ss_get_dz_num(address, my_dev->tparams.zns_zone_capacity); // starting block address of data zone to read from
        nlb_l = zns_dev->mdts / my_dev->lba_size_bytes;
        nlb_d = size / my_dev->lba_size_bytes;
        log_mdts_buffer = malloc(zns_dev->mdts);
        dz_sba = address / my_dev->lba_size_bytes; // starting block number for the datazone to read from (doesn't account for +3 log zone offset)

        // read all the data zones
        log_table_mutex.lock();
        int ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, dzlba, nlb_d, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, true);
        
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
                if (lb_vb_table.count(slba) > 0){
                        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb_l, log_mdts_buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, true);
                        int temp_slba = slba;
                        int temp_endlba = slba + nlb_l;

                        uint8_t * t_lz_buf = (uint8_t *) log_mdts_buffer;
                        uint8_t * t_dz_buf = (uint8_t *) buffer;

                        while (temp_slba < temp_endlba){
                                if (lb_vb_table.count(temp_slba) > 0){
                                        int vaddress = lb_vb_table[temp_slba];
                                        int dz_block_number = ( vaddress/ my_dev->lba_size_bytes) - dz_sba;
                                        int lz_block_number = temp_slba - slba;
                                        uint8_t * dz_lba_copy_ad = t_dz_buf + (dz_block_number * my_dev->lba_size_bytes);
                                        uint8_t * lz_lba_copy_ad = t_lz_buf + ( lz_block_number * my_dev->lba_size_bytes);
                                        mempcpy(dz_lba_copy_ad, lz_lba_copy_ad, my_dev->lba_size_bytes);


                                }
                                temp_slba += 1;
                        }
                }
                slba += nlb_l;
        }

        if (zns_dev->tail_lba < zns_dev->wlba && read_eval){
                slba = 0x00;
                endlba = zns_dev->wlba;
                read_eval = false;
                goto read_loop;
        }
        
        log_table_mutex.unlock();
        free(log_mdts_buffer);
        return ret;
}

int ss_write_lzdz(struct user_zns_device *my_dev, int lzslba){
        int nlb, zone_size, nr_dzones;
        void * log_zone_buffer, * data_zone_buffer;
        struct zns_dev_params * zns_dev;
        
        nr_dzones = my_dev->capacity_bytes / my_dev->lba_size_bytes; // number of data zones
        nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;
        zns_dev = (struct zns_dev_params *) (my_dev->_private);
        zone_size = my_dev->tparams.zns_zone_capacity;
       
        std::vector<bool> dz_read(zns_dev->log_zones + nr_dzones, false); 
        log_zone_buffer = malloc(zone_size);
        data_zone_buffer = malloc(zone_size);

        // reset log zone, copy log zone data and map data
        log_table_mutex.lock();
        int ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, lzslba, nlb, log_zone_buffer,zone_size, my_dev->lba_size_bytes, zns_dev->mdts, true);
        // error printing for ret
        
        std::unordered_map<uint64_t, uint64_t> log_table_c = log_table;
        for (int i = lzslba; i < lzslba+nlb; i++){
                int vb_ad = lb_vb_table[i];
                lb_vb_table.erase(i);
                log_table.erase(vb_ad);
        }
        // release semaphore
        log_table_mutex.unlock();


        // getting zones that need updating
        for (int i = lzslba; i < lzslba + nlb; i++){
                int t_dz_num = ss_get_dz_num(lb_vb_table[i], my_dev->tparams.zns_zone_capacity);
                dz_read[t_dz_num] = true;
        }

        // iterating though zones we need to read
        for (uint i = 3; i < dz_read.size(); i++){
                if (dz_read[i]){
                        dz_write_table[i] = true;
                        int dslba = i * nlb;  
                        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, dslba, nlb, data_zone_buffer, zone_size, my_dev->lba_size_bytes, zns_dev->mdts, true);
                        // error printing for ret
                        uint8_t * t_dz_buf = (uint8_t *) data_zone_buffer;
                        uint8_t * t_lz_buf = (uint8_t *) log_zone_buffer;

                        // get blocks in the log zone to be cleared that belong to a data zones's virtual address range
                        for (int j = i * zone_size; j < (i * zone_size) + my_dev->tparams.zns_zone_capacity; j+= my_dev->lba_size_bytes){
                                
                                if (log_table_c.count(j) > 0 && log_table_c[j] < (lzslba + nlb)){ 
                                        mempcpy(t_dz_buf, t_lz_buf, my_dev->lba_size_bytes);
                                }
                                
                                t_dz_buf += my_dev->lba_size_bytes;
                                t_lz_buf += my_dev->lba_size_bytes;
                        }

                        // reset the datazone and write fresh data to it
                        ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, (__u64) i*nlb, false, NVME_ZNS_ZSA_RESET, 0, nullptr);
                        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, i * nlb, nlb, data_zone_buffer, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->mdts, false);

                }
        }

        free(log_zone_buffer);
        free(data_zone_buffer);

        return ret;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev) {    
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    free(my_dev->_private);
    free(my_dev);
    // push metadata onto the device 
    return ret;
}

void gc_main(struct user_zns_device *my_dev) {
    
    struct zns_dev_params * zns_dev;

    zns_dev = (struct zns_dev_params *) my_dev->_private;
    int ret = -1;
    int gc_wmark = zns_dev->gc_wmark;
    int num_log_zones = zns_dev->log_zones;
    __u64 wlba = zns_dev->wlba;
    __u64 tail_lba = zns_dev->tail_lba;

    
    while (true) {
    // gc mutex lock
    gc_mutex.lock();
    gc_mutex.unlock();
    // call gc write func: ss_write_lzdz
    //ss_write_lzdz(my_dev, lzslba);
    // Logic for lzslba

    bool log_cleared = false;
    ret = ss_write_lzdz(my_dev, zns_dev->target_lzslba);
    if(ret != 0){
        printf("Error: ss_write_lzdz failed with lzslba of %ull \n", zns_dev->target_lzslba);
    }
        
    log_cleared = true;
    // gc mutex unlock
    

    //t //w //g  //////////////////////////

    // tail ptr update on reset
    if (log_cleared == true) {
        if (tail_lba == zns_dev->log_zones * zns_dev->num_bpz){
            tail_lba = 0x00 + zns_dev->num_bpz;
        } else {
            tail_lba += zns_dev->num_bpz;
        }
    }
 
    // stall writes if this condition [happens in write]
    // bool ptr_clash = false;
    // while (wlba == tail_lba){ }
    //     // 
     }

}

u_int32_t get_zone_saddr(uint64_t address, user_zns_device **my_dev){ //returns: start addr of the zone the addr belongs to

    uint32_t z_saddr = static_cast<uint32_t>(address / (*my_dev)->tparams.zns_zone_capacity);

    return z_saddr;

}

int which_zone_num(uint64_t address, user_zns_device **my_dev){ // returns: zone num an address is in 
    int start_addr_dzones;
    int z_num = (get_zone_saddr(address, my_dev) - start_addr_dzones);

    return z_num;

}


int init_ss_zns_device(struct zdev_init_params *params, struct user_zns_device **my_dev){    
    
    int ret = -ENOSYS;    
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(params);
    UNUSED(my_dev);
    struct nvme_id_ns ns{};
    *my_dev = (struct user_zns_device *) malloc(sizeof(struct user_zns_device));
    struct nvme_zone_report zns_report;
    struct zns_dev_params * zns_dev = (struct zns_dev_params *)malloc(sizeof(struct zns_dev_params));
    
    // Resize gc_table based on num of dz
    gc_table.resize((*my_dev)->tparams.zns_num_zones - params->log_zones);
    
    
    //zns_dev->num_bpz;
    // Open device and setup zns_dev_params
    zns_dev->dev_fd = nvme_open(params->name);
    ret = nvme_get_nsid(zns_dev->dev_fd, &zns_dev->dev_nsid);
    zns_dev->wlba = 0x00;
    zns_dev->target_lzslba = 0x00;
    zns_dev->tail_lba = params->log_zones * (*my_dev)->tparams.zns_zone_capacity; // tail ptr set to end of log zone
    zns_dev->gc_wmark = params->gc_wmark;
    zns_dev->log_zones = params->log_zones;


    // getting mdts 
    int mdts = ss_get_mdts(params->name, zns_dev->dev_fd);
    zns_dev->mdts = mdts;
   
    // Reset device
    ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid,(__u64)0x00, true, NVME_ZNS_ZSA_RESET, 0, nullptr);
       
    // Get testing_params
    ret = nvme_identify_ns(zns_dev->dev_fd, zns_dev->dev_nsid, &ns);
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[(ns.flbas & 0xf)].ds;
    
    ret = nvme_zns_mgmt_recv(zns_dev->dev_fd, (uint32_t) zns_dev->dev_nsid,0, NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL,0, sizeof(zns_report), (void *) &zns_report);

    nvme_zns_id_ns zns_ns;
    ret = nvme_zns_identify_ns(zns_dev->dev_fd, (uint32_t) zns_dev->dev_nsid, &zns_ns);
    struct nvme_zone_report * zn_rep_ptr = (struct nvme_zone_report *) &zns_report;
    
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zn_rep_ptr->nr_zones) - params->log_zones;
    zns_dev->num_bpz = le64_to_cpu(zns_ns.lbafe[(ns.flbas & 0xf)].zsze);
    (*my_dev)->tparams.zns_zone_capacity = zns_dev->num_bpz * (*my_dev)->tparams.zns_lba_size; // number of writable blocks into lba size (bytes)

    // adding user visible properties
    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    (*my_dev)->capacity_bytes = (*my_dev)->tparams.zns_zone_capacity * (*my_dev)->tparams.zns_num_zones ;

    // get the metadata (implement later as device is completely empty)

    (*my_dev)->_private = (void *) zns_dev;
    //printf("mdts block cap is %i, mdts is %i, mpsmin is %i", mdts/(*my_dev)->lba_size_bytes, mdts, mpsmin);
    
    // Start the GC thread
    gc_thread = std::thread(gc_main,*my_dev);
 
    return ret;
        
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int ret = -ENOSYS;    
    // //this is to supress gcc warnings, remove it when you complete this function     
    // UNUSED(my_dev);
    // UNUSED(address);
    // UNUSED(buffer);
    // UNUSED(size);

    //return ret;

    struct zns_dev_params * zns_dev = (struct zns_dev_params *) my_dev->_private;

    // Check if block aligned
    if (address % my_dev->lba_size_bytes != 0 || size % my_dev->lba_size_bytes != 0) {
        printf("ERROR: read request is not block aligned \n");
        return -EINVAL;
    }

    int cur_address = address;
    int next_address = address; 
    int end_address = cur_address + size;
    int nlb = 1;
    uint8_t * buf_ad = (uint8_t*) buffer;


    // call data zone read function
    //
    // read blocks from log table and update with latest blocks
    //

    ret = ss_read_lzdz(my_dev,address, buffer, size);
    return ret;

    while(next_address != end_address){
            int previous_address = next_address;
            next_address += my_dev->lba_size_bytes;
           
            // checking if the previous logical pages are logical contiguous blocks in the nvme device
            if ((log_table[next_address] - log_table[previous_address]) != 1 || next_address == end_address){ 
                   ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, log_table[cur_address], nlb, buf_ad, (nlb * my_dev->lba_size_bytes), my_dev->lba_size_bytes, zns_dev->mdts, true); 
                    buf_ad += (nlb * my_dev->lba_size_bytes)/my_dev->lba_size_bytes; 
                    nlb = 1;
                    cur_address = next_address;
            } else {
                     nlb += 1;
            }
    }

    return ret;
}


int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function   
    struct zns_dev_params * zns_dev = (struct zns_dev_params *) (my_dev->_private);
    // Check if block aligned
    if (address % my_dev->lba_size_bytes != 0 || size % my_dev->lba_size_bytes != 0) {
        printf("ERROR: read request is not block aligned \n");
        return -EINVAL;
    }
        
    int nlb = size / my_dev->lba_size_bytes;
    //printf("The size to write is %i and address is %lu\n, wlba address is %llu, nlb is %i",size, address, zns_dev->wlba, nlb);
    ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, zns_dev->wlba, nlb, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts,false);
    //printf("the error is %i %s\n", ret, nvme_status_to_string(ret,false));
    
    // updating to the next wlba
    __u64 temp_wlba = zns_dev->wlba;
    __u64 temp_address = address;

    // GC_trigger 
    int gc_wmark = zns_dev->gc_wmark * zns_dev->num_bpz; // granularity of blocks
    int num_log_zones = zns_dev->log_zones;
    __u64 wlba = zns_dev->wlba;
    //__u64 tail_lba = zns_dev->tail_lba;

    if (wlba >= gc_wmark){ 
        __u64 target_lzslba = zns_dev->target_lzslba; // target_lzslba is the start addr of the log zone to be cleared
        
        if (target_lzslba + zns_dev->num_bpz >= num_log_zones * zns_dev->num_bpz){ // checking if last zone was the one cleared
            zns_dev->target_lzslba = 0x00;
        }else {
            zns_dev->target_lzslba += zns_dev->num_bpz; // update target_lzslba to start of next block
        }
        // gc mutex unlock 
        gc_mutex.unlock();
          

       // gc mutex lock
       gc_mutex.lock();
    }

 
    // adding mappings to the log table
    log_table_mutex.lock();
    for (int i = 0; i < nlb; i++){
            if (log_table.count(temp_address) > 0){
                    log_table[temp_address] = temp_wlba;
                    lb_vb_table[temp_wlba] = temp_address;
                    } else {
                    log_table.insert(std::make_pair(temp_address, temp_wlba));
                    lb_vb_table.insert(std::make_pair(temp_wlba, temp_address));
            }
            
            //update both wlba and address by logical block size
            temp_wlba += 1;
            // if wlba == threshold, if threshold reached, activate semaphore
            temp_address += my_dev->lba_size_bytes;
    }    
    log_table_mutex.unlock();
    return ret;
}

}

