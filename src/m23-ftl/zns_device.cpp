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
#include <nvme/ioctl.h>
#include <nvme/types.h>
#include <nvme/util.h>

#include "zns_device.h"
#include "../common/unused.h"

extern "C" {

int dev_fd = 0;
__u32 dev_nsid = 0;

int deinit_ss_zns_device(struct user_zns_device *my_dev) {    
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(my_dev);

    // push metadata onto the device
 
    return ret;
}

int init_ss_zns_device(struct zdev_init_params *params, struct user_zns_device **my_dev){    
    int ret = -ENOSYS;    
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(params);
    UNUSED(my_dev);
    struct nvme_id_ns ns{};
    struct user_zns_device *t_my_dev = new user_zns_device {};
    struct nvme_zone_report zns_report; 
    // open device
    
    dev_fd = nvme_open(params->name);
    ret = nvme_get_nsid(dev_fd, &dev_nsid); 
    
    // reset device
    ret = nvme_zns_mgmt_send(dev_fd, dev_nsid,(__u64)0x00, true, NVME_ZNS_ZSA_RESET, 0, nullptr);
       
    // get testing_params
    ret = nvme_identify_ns(dev_fd, dev_nsid, &ns);
    *my_dev = t_my_dev;
    t_my_dev->tparams.zns_lba_size = 1 << ns.lbaf[(ns.flbas & 0xf)].ds;
    
    ret = nvme_zns_mgmt_recv(dev_fd, (uint32_t) dev_fd,0, NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL,0, sizeof(zns_report), (void *) &zns_report);

    struct nvme_zone_report * zn_rep_ptr = (struct nvme_zone_report *) &zns_report;
    int num_zones = le64_to_cpu(zn_rep_ptr->nr_zones);
    t_my_dev->tparams.zns_num_zones = num_zones;
    t_my_dev->tparams.zns_zone_capacity = le64_to_cpu(zn_rep_ptr->entries[0].zcap);

    // adding user visible properties
    t_my_dev->lba_size_bytes = t_my_dev->tparams.zns_lba_size;
    t_my_dev->capacity_bytes = (num_zones - params->log_zones - 1) * t_my_dev->lba_size_bytes;

    // get the metadata (implement later as device is completely empty)
    
    return ret;    
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int ret = -ENOSYS;    
    // this is to supress gcc warnings, remove it when you complete this function     
    UNUSED(my_dev);
    UNUSED(address);
    UNUSED(buffer);
    UNUSED(size);

    // using log table get physical address

    return ret;
}
int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function     
    UNUSED(my_dev);
    UNUSED(address);
    UNUSED(buffer);
    UNUSED(size);

    // using log table get physical address
    
    return ret;
}

}
