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

#include <assert.h>
#include <cstdint>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libnvme.h>
#include <nvme/ioctl.h>
#include <nvme/tree.h>
#include <nvme/types.h>
#include <nvme/util.h>

#include "m1_assignment.h"
#include "../common/unused.h"

extern "C"
{

int ss_nvme_device_io_with_mdts(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size, uint64_t lba_size, uint64_t mdts_size, bool read){
    UNUSED(numbers);

        int ret = -ENOSYS, num_io, io_size, nlb;
    uint8_t * buf;
    // this is to supress gcc warnings, remove it when you complete this function 
   if (mdts_size < buf_size){
           num_io = buf_size / mdts_size;
           io_size = mdts_size;
   } else {
           num_io = 1;
           io_size = buf_size;
   }

   nlb = io_size / lba_size;
   buf = (uint8_t *) buffer;

    if (read){
            //printf("starting lba is %i, total lba is %i\n", slba, numbers);
            for (int i = 0; i < num_io; i++){
                    ret = ss_nvme_device_read(fd, nsid, slba, nlb, buf, io_size);
                    buf += io_size;
                    update_lba(slba, lba_size, nlb);
            }
    } else {
        for (int i = 0; i < num_io; i++){
                    ret = ss_nvme_device_write(fd, nsid, slba, nlb, buf, io_size);
                    buf += io_size;
                    update_lba(slba, lba_size, nlb);
        }
    }
    return ret;
}


int ss_nvme_device_read(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size) {
    int ret = -ENOSYS;
        // this is to supress gcc warnings, remove it when you complete this function    
        ret = nvme_read(fd, nsid, slba, numbers - 1, 0, 0, 0, 0, 0, buf_size, buffer, 0, nullptr);
    return ret;
}

int ss_nvme_device_write(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size) {
        int ret = -ENOSYS;
        ret = nvme_write(fd, nsid, slba, numbers - 1, 0, 0, 0, 0, 0, 0, buf_size, buffer, 0, nullptr);
        return ret;
}

int ss_zns_device_zone_reset(int fd, uint32_t nsid, uint64_t slba) {
    int ret = -ENOSYS;
    ret = nvme_zns_mgmt_send(fd, nsid, slba, false, NVME_ZNS_ZSA_RESET, 0, nullptr);                return ret;
}

// this does not take slba because it will return that
int ss_zns_device_zone_append(int fd, uint32_t nsid, uint64_t zslba, int numbers, void *buffer, uint32_t buf_size, uint64_t *written_slba){
    //see section 4.5 how to write an append command
 
    int ret = -ENOSYS;
    void *ptr = (void *) written_slba;
    __u64 *written_slba_2 = (__u64 *) ptr;
    
    ret = nvme_zns_append(fd, nsid, zslba, numbers - 1, 0, 0, 0, 0, buf_size, buffer, 0, nullptr, written_slba_2);    
    return ret;
}

void update_lba(uint64_t &write_lba, const uint32_t lba_size, const int count){
    UNUSED(lba_size); 
    write_lba += count; 
}

// see 5.15.2.2 Identify Controller data structure (CNS 01h)
// see how to pass any number of variables in a C/C++ program https://stackoverflow.com/questions/1579719/variable-number-of-parameters-in-function-in-c
// feel free to pass any relevant function parameter to this function extract MDTS 
// you must return the MDTS as the return value of this function 
uint64_t get_mdts_size(int count, ...){ 

        // doesn't work with m1, works with m2 as right device name is sent

        va_list args;
        va_start(args,count);

        const char *dev_name = va_arg(args, char *);
        printf("%s", dev_name);
        const int dev_fd = va_arg(args,int); 

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

}
