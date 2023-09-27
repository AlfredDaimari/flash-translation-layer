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
#include "../m1/m1_assignment.h"

std::vector<long long int> log_table;
std::vector<bool> data_zone_table; // data_zone_table: len = num data zones

std::thread gc_thread;
std::condition_variable cv;
std::mutex log_table_mutex;
std::mutex gc_mutex;
bool lz1_cleared;
bool clear_lz1;
bool gc_shutdown;

extern "C" {

// returns the logical zone where the virtual address belongs in
int ss_get_dz(uint64_t address, int zone_size_in_bytes, int num_of_log_zones){

        return (address / zone_size_in_bytes) + num_of_log_zones;
}

// get the data zone lba for an address
int ss_get_ad_dz_lba(uint64_t address, int zone_size_in_bytes, int lba_size, int num_of_log_zones){
        int dz_lba = address / lba_size;
        int log_lba_offset = (zone_size_in_bytes * num_of_log_zones) / lba_size;
        return log_lba_offset + dz_lba;
}

// get the slba for an address' datazone
int ss_get_dz_slba(uint64_t address, int zone_size_in_bytes, int bpz, int num_of_log_zones){
        //bpz = num of blocks per zone
        int dz = (address/zone_size_in_bytes) + num_of_log_zones;
        return dz * bpz;
}

// number of free logical blocks in log zones
int ss_get_logzone_free_lb(int wlba, int tail_lba, int end_lba){
        if (wlba > tail_lba){
                return tail_lba + ( end_lba - wlba);
        } 
                return tail_lba - wlba;
}

// updates log table with addresses or -1
void ss_update_log_table(int nlb, uint64_t address, int slba, int lba_size, bool set_false){
// adding mappings to the log table
        
    if (set_false){
            for (int i = slba; i < slba + nlb; i++){
                    log_table[i] = -1;
            }
    }

    for (int i = slba; i < slba + nlb; i++){
            log_table[i] = address;            //update both wlba and address by logical block size 
            address += lba_size;
    }  
}

// returns the first valid mapping in the log table for an address space
int get_valid_address_from_log_table(uint64_t address, uint64_t end_address, int lba_size, std::unordered_map<uint64_t, uint64_t>log_table_map){ 
        uint64_t current_address = address;

        while(current_address != end_address){
                if (log_table_map.count(current_address) > 0){
                        return current_address;
                }
                current_address += lba_size;
        }

        return current_address;
}

// more than one block is read only when two contiguos vb is contiguous in the log zone (can be optimized much better)
// func reads from log zone using an slba or address space
// log_table_map <- this contains a mapping of addresses to lbas
int ss_read_from_log_zone(user_zns_device *my_dev, uint64_t address, int slba, void *buffer, int size, int nlb, bool read_address, std::unordered_map<uint64_t, uint64_t> log_table_map){
        int ret;
        
        struct zns_dev_params * zns_dev = (struct zns_dev_params *) my_dev->_private;

        // read virtual address blocks in the log zone
        if (read_address){

                int cur_address = address, fst_cogu_address, next_address, end_address = address + size;
                uint8_t * buf_t; 
                int t_nlb = 1;

                // finding the first valid virtual address in the log zone
                cur_address = get_valid_address_from_log_table(address, end_address, my_dev->lba_size_bytes, log_table_map);
                if (cur_address == end_address)
                        return 0;

                fst_cogu_address = cur_address;

                while(cur_address != end_address){

                        next_address = cur_address + my_dev->lba_size_bytes;

                        // when the next address is not present in the log zone 
                        if (log_table_map.count(next_address) == 0){
                                // getting position of address in buffer
                                int in_buffer_lba_size_offset = ss_get_ad_dz_lba(fst_cogu_address, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->log_zones) - ss_get_dz_slba(fst_cogu_address, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->log_zones);

                                buf_t = ((uint8_t *) buffer) +  in_buffer_lba_size_offset * my_dev->lba_size_bytes;
                                ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, log_table_map[fst_cogu_address], t_nlb, buf_t, t_nlb * my_dev->lba_size_bytes, my_dev->lba_size_bytes, zns_dev->mdts, true);
                                cur_address = get_valid_address_from_log_table(next_address, end_address, my_dev->lba_size_bytes, log_table_map);
                                fst_cogu_address = cur_address;
                                t_nlb = 1;
                        }
           
                        // when the current and next logical blocks are not contiguous
                        if ((log_table[next_address] - log_table[cur_address]) != 1 || next_address == end_address){ 
                                int in_buffer_lba_size_offset = ss_get_ad_dz_lba(fst_cogu_address, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->log_zones) - ss_get_dz_slba(fst_cogu_address, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->log_zones);
                                buf_t = ((uint8_t *) buffer) +  in_buffer_lba_size_offset * my_dev->lba_size_bytes;
                                
                                ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, log_table[cur_address], nlb, buf_t, (nlb * my_dev->lba_size_bytes), my_dev->lba_size_bytes, zns_dev->mdts, true);  
                                nlb = 1;
                                cur_address = next_address;
                        } else {
                                // virtual address blocks in log zone are contiguous
                                nlb += 1;
                        }
                }

                return ret;
        }
        
        // error checking if read goes beyond defined log zone
        if (slba + nlb > zns_dev->log_zones * zns_dev->num_bpz){
                printf("Error: reading is going beyond the log zones");
                return -1;
        }

        // reading using given starting slba
        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, true);
        return ret;
}

// func notifies the gc thread if zones need clearing, updates the wlba
// performs write on a circular log zone
int ss_write_to_log_zone(user_zns_device *my_dev, uint64_t address, void *buffer, int size){
        int ret = -ENOSYS, free_log_lb, elba, nlb;

        struct zns_dev_params * zns_dev = (struct zns_dev_params *)my_dev->_private;

        elba = zns_dev->log_zones * zns_dev->num_bpz;    // ending lba of log zone
        free_log_lb = ss_get_logzone_free_lb(zns_dev->wlba, zns_dev->tail_lba, elba);
        
        // clear log lbs until the minimum requirement for log zones is hit
        while (free_log_lb < zns_dev->gc_wmark_lb){
                clear_lz1 = true;         
                cv.notify_one(); // notify gc to run, wait until reset
                {
                    std::unique_lock<std::mutex> lk(gc_mutex);
                    cv.wait(lk, []{return lz1_cleared;});
                }
                lz1_cleared = false;

                free_log_lb = ss_get_logzone_free_lb(zns_dev->wlba, zns_dev->tail_lba, elba);
        }

        // when log zone is not sequential
        if (zns_dev->wlba > zns_dev->tail_lba){
                int rem_size;
                int slba = zns_dev->wlba;
                int size_bytes_slba_elba = (elba - slba) * my_dev->lba_size_bytes;

                if (size <= size_bytes_slba_elba){
                        nlb = size / my_dev->lba_size_bytes;
                        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, false);
                        ss_update_log_table(nlb, address, slba, my_dev->lba_size_bytes, false);

                        zns_dev->wlba += nlb;
                        
                        if (zns_dev->wlba == elba)
                                zns_dev->wlba = 0x00;

                        return ret;
                }

                nlb = elba - slba;
                ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, false);
                ss_update_log_table(nlb, address, slba, my_dev->lba_size_bytes, false);

                // pointing to remainder of buffer
                uint8_t * rem_buffer = ((uint8_t *) buffer) + size_bytes_slba_elba;
                rem_size = size - size_bytes_slba_elba;
                int rem_address_st = address + rem_size;

                // write remaining buffer to log zone
                nlb = (rem_size) / my_dev->lba_size_bytes;
                ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, 0x00, nlb, rem_buffer,rem_size, my_dev->lba_size_bytes, zns_dev->mdts, false);
                ss_update_log_table(nlb, rem_address_st, 0x00, my_dev->lba_size_bytes, false);
                zns_dev->wlba = nlb;

                return ret;
                 
        }

        // write normally as log zone is currently sequential
        nlb = size / my_dev->lba_size_bytes;
        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, zns_dev->wlba, nlb, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, false);
        ss_update_log_table(nlb, address, zns_dev->wlba, my_dev->lba_size_bytes, false);
        zns_dev->wlba += nlb;
        return ret;
}

// read from data_zone
int ss_read_from_data_zone(struct user_zns_device *my_dev, uint64_t address, void * buffer, int size){
                
        int ret, nlb, slba;
        struct zns_dev_params * zns_dev;

        zns_dev = (struct zns_dev_params *) my_dev->_private;
        
        nlb = size / my_dev->lba_size_bytes;
        slba = ss_get_ad_dz_lba(address, my_dev->tparams.zns_zone_capacity, zns_dev->num_bpz, zns_dev->log_zones);
        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, true);

        return ret;
}

// write to one full data zone
int ss_write_to_data_zone(struct user_zns_device *my_dev, uint64_t address, void *buffer, int size){
        
        // check if size is in line with data zone size

        int ret, nlb, slba;
        struct zns_dev_params * zns_dev;

        zns_dev = (struct zns_dev_params *) my_dev->_private;
       
        if (size != my_dev->tparams.zns_zone_capacity){
                printf("Error: only zone size writes allowed in data zone");
                return -1;
        }

        nlb = size / my_dev->lba_size_bytes;
        slba = ss_get_dz_slba(address, my_dev->tparams.zns_zone_capacity, zns_dev->num_bpz, zns_dev->log_zones);
        ret = ss_nvme_device_io_with_mdts(zns_dev->dev_fd, zns_dev->dev_nsid, slba, nlb, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts, true);

        return ret;

}

int ss_read_lzdz(struct user_zns_device *my_dev, uint64_t address, std::vector<char> &buffer, int size){
        int nlb_mdts, dz_slba, slba, ret;
        struct zns_dev_params * zns_dev;
        
        zns_dev = (struct zns_dev_params *) my_dev->_private;
        dz_slba = ss_get_adr_dz_slba(address, my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->log_zones); // starting block address of data zone to read from 
        nlb_mdts = zns_dev->mdts / my_dev->lba_size_bytes;
        std::vector<char> log_mdts_buffer(zns_dev->mdts);
       
        // read from data_zone if it has been writes to it
        int dz = ( address / my_dev->tparams.zns_zone_capacity ) + zns_dev->log_zones;
       
 log_table_mutex.lock();
        if (gc_table[dz])
                ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, dz_slba, 0, buffer.data(), size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);
        

        slba = 0;
        
        while(slba < log_table.size()){

                // read mtds blocks if slba_va exists in range
                int vb = log_table[slba];
                
                // if block doesn't belong to zone continue
                if (vb == -1 || vb < address || vb > address + size){
                        slba += 1;
                        continue;
                }

                // read mdts size data from log_zone
                ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, slba, 0, log_mdts_buffer.data(), size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);
                int temp_slba = slba;
                int temp_endlba = (slba + nlb_mdts) < log_table.size() ? slba + nlb_mdts : log_table.size();

                while (temp_slba < temp_endlba){

                        // read if slba from mdts buffer if it exists in range
                        int temp_slba_vb = log_table[temp_slba];
                        
                   
                        if (temp_slba_vb >= address && temp_slba_vb < (address + size)){
                                
                                int vb = log_table[temp_slba];
                                int buf_offset = ( vb - address) / my_dev->lba_size_bytes;
                                int lz_block_offset = temp_slba - slba;
                                
                                auto startIter = log_mdts_buffer.begin() + (lz_block_offset * my_dev->lba_size_bytes);
                                auto endIter = log_mdts_buffer.begin() + (lz_block_offset * my_dev->lba_size_bytes) + my_dev->lba_size_bytes;
                                auto buf_Iter = buffer.begin() + (buf_offset * my_dev->lba_size_bytes);

                                std::copy(startIter, endIter, buf_Iter);
                        }
                        temp_slba += 1;
                }
                
                slba += nlb_mdts; //update with nlb_mdts size as we have checked mdts chunk
                
        }

        log_table_mutex.unlock();

        return ret;
}

int ss_write_reset_lz(struct user_zns_device *my_dev, int lzslba,std::vector<bool> &dz_read, void * log_zone_buffer){
        int nlb, zone_size; 
        struct zns_dev_params * zns_dev;

        nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;
        zone_size = my_dev->tparams.zns_zone_capacity; 
        zns_dev = (struct zns_dev_params *) (my_dev->_private);
       
        // reset log zone, delete entries in log_map         
               
        int ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, lzslba, 0, log_zone_buffer, zone_size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);        
        for (int i = lzslba; i < lzslba+nlb; i++){
                int vb_ad = log_table[i];
                int t_dz_num = ss_get_dz_num(vb_ad, my_dev->tparams.zns_zone_capacity, zns_dev->log_zones);
                dz_read[t_dz_num] = true;
               
                log_table[i] = -1; 
        }
 
        ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, lzslba, false, NVME_ZNS_ZSA_RESET, 0, nullptr); // reset zone
        return ret;
}

int ss_write_lz_buf_dz(struct user_zns_device *my_dev, int lzslba, std::vector<long long int> log_table_c,std::vector<bool>dz_read, std::vector<char> log_zone_buffer){
        int nlb, zone_size,ret; 
        struct zns_dev_params * zns_dev;
       
        nlb = my_dev->tparams.zns_zone_capacity / my_dev->lba_size_bytes;
        zns_dev = (struct zns_dev_params *) (my_dev->_private);
        zone_size = my_dev->tparams.zns_zone_capacity;
        std::vector<char> data_zone_buffer(zone_size);

        // iterating though zones we need to read
        for (int i = zns_dev->log_zones; i < dz_read.size(); i++){
                if (dz_read[i]){
                      
                        // read from dz if writes exist
                        int dslba = i * nlb;
                                                
                        if (gc_table[i] == true)
                                ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, dslba, 0, data_zone_buffer.data(), zone_size, my_dev->lba_size_bytes, zns_dev->mdts, true, false);
                        // error printing for ret 
                        // go through log zone and apply lba blocks onto read data zone buffer
                        for (int j = lzslba; j < lzslba + nlb; j++){
                                
                                if (log_table_c[j] == -1) 
                                       continue; 
                                
                                int vb = log_table_c[j];
                                int data_zone_vb = (i - zns_dev->log_zones) * zone_size;

                                // apply the lb to data zone buffer if it exists in address space
                                if (vb >= data_zone_vb && vb < data_zone_vb + zone_size)
                                {
                                        int dz_lba_offset = ss_get_adr_dz_slba(vb, zone_size, my_dev->lba_size_bytes, zns_dev->log_zones);
                                        int dz_slba = ((data_zone_vb / zone_size) + zns_dev->log_zones) * zns_dev->num_bpz; 
                                    
                                        int log_offset = (j - lzslba);
                                        int data_offset = (dz_lba_offset - dz_slba);

                                        auto startIter = log_zone_buffer.begin() + (log_offset * my_dev->lba_size_bytes);
                                        auto endIter = log_zone_buffer.begin() + (log_offset * my_dev->lba_size_bytes) + my_dev->lba_size_bytes;

                                        auto data_iter = data_zone_buffer.begin() + (data_offset * my_dev->lba_size_bytes);

                                        std::copy(startIter, endIter, data_iter);
                                }
                           
                        }
                        
                        // reset the datazone and write fresh data to it
                        ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid, (__u64) i*nlb, false, NVME_ZNS_ZSA_RESET, 0, nullptr);
                        ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, i * nlb, 0, data_zone_buffer.data(), my_dev->tparams.zns_zone_capacity, my_dev->lba_size_bytes, zns_dev->mdts, false, false);
                        gc_table[i] = true; // data_zone now has entries
                }
        }
 
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
    int ret, nr_dzones, c_target_lzslba;
    __u64 end_lba;

    zns_dev = (struct zns_dev_params *) my_dev->_private;
    ret = -1;
    nr_dzones = my_dev->capacity_bytes / my_dev->tparams.zns_zone_capacity;
    end_lba = zns_dev->log_zones * zns_dev->num_bpz; // lba where log zone ends

    
    while (true && !gc_shutdown) {

        std::unique_lock<std::mutex> lk(gc_mutex);
        cv.wait(lk, []{return clear_lz1;});
   
        std::vector<long long int> log_table_c;
        std::vector<bool> dz_read(zns_dev->log_zones + nr_dzones, false);
        std::vector<char> log_zone_buffer(my_dev->tparams.zns_zone_capacity);

        log_table_mutex.lock();
        log_table_c = log_table; // copy for gc to use 
        
        ss_write_reset_lz(my_dev,zns_dev->target_lzslba, dz_read, log_zone_buffer.data());
        log_table_mutex.unlock();

        // tail lba update on reset
        if (zns_dev->tail_lba == end_lba){
                zns_dev->tail_lba = 0x00 + zns_dev->num_bpz;
        } else {
                zns_dev->tail_lba += zns_dev->num_bpz;
        }

        if (zns_dev->target_lzslba + zns_dev->num_bpz == end_lba){ // checking if last zone was the one cleared
                c_target_lzslba = zns_dev->target_lzslba;
                zns_dev->target_lzslba = 0x00;
        } else {
                c_target_lzslba = zns_dev->target_lzslba;
                zns_dev->target_lzslba += zns_dev->num_bpz; // update target_lzslba to start of next block
        }

        clear_lz1 = false;
        lz1_cleared = true;
        
        lk.unlock(); 
        cv.notify_one(); // notify write thread to start writing after reset

        ss_write_lz_buf_dz(my_dev, c_target_lzslba, log_table_c, dz_read, log_zone_buffer);

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
    int mdts = get_mdts_size(2, params->name, zns_dev->dev_fd);
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
    zns_dev->gc_wmark_lb = params->gc_wmark * zns_dev->num_bpz;    // gc_wmark logical block address
    zns_dev->tail_lba = params->log_zones * zns_dev->num_bpz; // tail lba set to end of log zone

    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    (*my_dev)->capacity_bytes = (*my_dev)->tparams.zns_zone_capacity * (*my_dev)->tparams.zns_num_zones; // writable size of device in bytes 

    (*my_dev)->_private = (void *) zns_dev;
    int gc_table_size = (*my_dev)->tparams.zns_num_zones + zns_dev->log_zones;
    
    data_zone_table = std::vector<bool>(gc_table_size);
    log_table = std::vector<long long int>(zns_dev->log_zones * zns_dev->num_bpz, -1);

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

    std::vector<char> buf_vec(size);

    ret = ss_read_lzdz(my_dev, address, buf_vec, size);
    memcpy(buffer, buf_vec.data(), size);
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
 
    log_table_mutex.lock();
    // write to device when there are enough free blocks
    ret = ss_nvme_device_io_with_mdts(my_dev, zns_dev->dev_fd, zns_dev->dev_nsid, zns_dev->wlba, address, buffer, size, my_dev->lba_size_bytes, zns_dev->mdts,false, true);
    log_table_mutex.unlock();


    return ret;
}

}

