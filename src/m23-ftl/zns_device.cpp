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
#include <libnvme.h>
#include <cstdlib>
#include <nvme/ioctl.h>
#include <nvme/util.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "zns_device.h"
#include "../common/unused.h"

std::unordered_map<uint64_t, uint64_t> log_table = {};
std::vector<uint64_t> invalid_table = {};

extern "C" {

int deinit_ss_zns_device(struct user_zns_device *my_dev) {    
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(my_dev);
    free(my_dev->_private);
    free(my_dev);
    // push metadata onto the device 
    return ret;
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
    
    nvme_id_ctrl identify_ctrl;
    int ret = nvme_identify_ctrl(zns_dev->dev_fd, &identify_ctrl);
    if (ret != 0) {
        std::cerr << "ERROR: Could not get nvme idenitfy control: "
                << std::to_string(ret) << std::endl;
    }

    void *registers = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, zns_dev->dev_fd, 0);;
    __u64 cap = le64_to_cpu((*(__le64 *)registers));
    munmap(registers, getpagesize());

    __u32 mpsmin = ((__u8 *)&cap)[6] & 0x0F;
    __u32 cap_mpsmin = 1 << (12 + mpsmin);
    uint64_t mdts = (1 << (identify_ctrl.mdts - 1)) * cap_mpsmin;
    zns_dev->mdts = mdts;

    
    // open device and setup zns_dev_params
    zns_dev->dev_fd = nvme_open(params->name);
    ret = nvme_get_nsid(zns_dev->dev_fd, &zns_dev->dev_nsid);
    zns_dev->wlba = 0x00;
    
    // reset device
    ret = nvme_zns_mgmt_send(zns_dev->dev_fd, zns_dev->dev_nsid,(__u64)0x00, true, NVME_ZNS_ZSA_RESET, 0, nullptr);
       
    // get testing_params
    ret = nvme_identify_ns(zns_dev->dev_fd, zns_dev->dev_nsid, &ns);
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[(ns.flbas & 0xf)].ds;
    
    ret = nvme_zns_mgmt_recv(zns_dev->dev_fd, (uint32_t) zns_dev->dev_nsid,0, NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL,0, sizeof(zns_report), (void *) &zns_report);

    nvme_zns_id_ns zns_ns;
    ret = nvme_zns_identify_ns(zns_dev->dev_fd, (uint32_t) zns_dev->dev_nsid, &zns_ns);
    struct nvme_zone_report * zn_rep_ptr = (struct nvme_zone_report *) &zns_report;
    
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zn_rep_ptr->nr_zones) - params->log_zones;
    (*my_dev)->tparams.zns_zone_capacity = le64_to_cpu(zns_ns.lbafe[(ns.flbas & 0xf)].zsze) * (*my_dev)->tparams.zns_lba_size; // number of writable blocks into lba size (bytes)

    // adding user visible properties
    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    (*my_dev)->capacity_bytes = (*my_dev)->tparams.zns_zone_capacity * (*my_dev)->tparams.zns_num_zones ;

    // get the metadata (implement later as device is completely empty)

    (*my_dev)->_private = (void *) zns_dev; 
    
    return ret;
        
}

int zns_udevice_read2(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int ret = -ENOSYS;    
    // //this is to supress gcc warnings, remove it when you complete this function     
    // UNUSED(my_dev);
    // UNUSED(address);
    // UNUSED(buffer);
    // UNUSED(size);

    //return ret;

    struct zns_dev_params * zns_dev_tmp = (struct zns_dev_params *) my_dev->_private;

    // Check if block aligned
    if (address % my_dev->lba_size_bytes != 0 || size % my_dev->lba_size_bytes != 0) {
        printf("ERROR: read request is not block aligned \n");
        return -EINVAL;
    }
    int zlbas = my_dev->tparams.zns_lba_size;
    //int nlb = size / zlbas;
    
    // nvme_read(zns_dev_tmp->dev_fd, zns_dev_tmp->dev_nsid, slba,nlb-1, 0, 0, 0, 0, 0, size, buffer, 0, NULL)

    //check log table for given lba(s)
    std::vector<std::pair<uint64_t, uint64_t>> contiguousRanges; //vector to store the contigous ranges
    
    uint64_t start_bpa = log_table[address];
    //printf("I AM HERE 1: %lld \n", start_bpa);
    uint64_t end_bpa = start_bpa + zlbas; // size acc to p block size
    //printf("I AM HERE 2: %lld \n", end_bpa);
    uint64_t start_address = address;
    uint64_t end_address = address;
    

    while (end_address < log_table[start_address] + size){
        //printf("I AM HERE 3: %lld \n", log_table[end_address]);
        if (log_table[end_address + zlbas] == end_bpa){
            end_bpa += zlbas;

        }else{
            break;
        }
        end_address += zlbas;
    }
    contiguousRanges.push_back({start_address, end_address});
    //printf("I AM HERE 4:%lld, %lld \n", contiguousRanges[0].first, contiguousRanges[0].second);
    for (uint64_t i = 0; i < contiguousRanges.size(); i++){
        printf("I AM HERE 4:%lld\n", i );
        uint64_t t_slba = contiguousRanges[i].first;
        uint64_t t_elba = contiguousRanges[i].second;
        uint64_t t_nlb = (t_elba - t_slba)/zlbas;
        if (t_nlb == 0){ t_nlb = 1;}
        ret = nvme_read(zns_dev_tmp->dev_fd, zns_dev_tmp->dev_nsid, t_slba,t_nlb-1, 0, 0, 0, 0, 0, t_nlb * zlbas, buffer, 0, NULL);
    }

    //nvme_read(zns_dev_tmp->dev_fd, zns_dev_tmp->dev_nsid, start_address,nlb-1, 0, 0, 0, 0, 0, size, buffer, 0, NULL)
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

    struct zns_dev_params * zns_dev_tmp = (struct zns_dev_params *) my_dev->_private;

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

    while(next_address != end_address){
            int previous_address = next_address;
            next_address = next_address + my_dev->lba_size_bytes;
           
            // checking if the previous logical pages are logical contiguous blocks in the nvme device
            if ((log_table[next_address] - log_table[previous_address]) != 1 || next_address == end_address){ 
                    ret = nvme_read(zns_dev_tmp->dev_fd, zns_dev_tmp->dev_nsid, log_table[cur_address], nlb-1, 0, 0, 0, 0, 0, nlb * my_dev->lba_size_bytes, buf_ad, 0, NULL);
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
        
    int nlb = size / my_dev->lba_size_bytes;
    //printf("The size to write is %i and address is %lu\n, wlba address is %llu, nlb is %i",size, address, zns_dev->wlba, nlb);
    ret = nvme_write(zns_dev->dev_fd, zns_dev->dev_nsid, zns_dev->wlba, nlb-1, 0, 0, 0, 0, 0, 0, size, buffer, 0, nullptr);
    //printf("the error is %i %s\n", ret, nvme_status_to_string(ret,false));
    if(ret != 0){
        printf("The error is %s, current wlba is %lu \n", nvme_status_to_string(ret, false), zns_dev->wlba);
    }
    // updating to the next wlba
    __u64 temp_wlba = zns_dev->wlba;
    __u64 temp_address = address;
 
    // adding mappings to the log table
    for (int i = 0; i < nlb; i++){
            if (log_table.count(temp_address) > 0){
                    log_table.emplace(temp_address, temp_wlba);
                    invalid_table.push_back((uint64_t)temp_wlba);
            } else {
                    log_table.insert(std::make_pair(temp_address, temp_wlba));
            }
            
            //update both wlba and address by logical block size
            temp_wlba += 1;
            temp_address += my_dev->lba_size_bytes;
    }
    // updating the real wlba
    zns_dev->wlba = temp_wlba;

    return ret;
}

}
