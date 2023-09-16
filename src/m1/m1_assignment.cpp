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
#include <errno.h>
#include <stdio.h>

#include "m1_assignment.h"
#include "../common/unused.h"

extern "C"
{

int ss_nvme_device_io_with_mdts(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size,
                                uint64_t lba_size, uint64_t mdts_size, bool read){
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(fd);
    UNUSED(nsid);
    UNUSED(slba);
    UNUSED(numbers);
    UNUSED(buffer);
    UNUSED(buf_size);
    UNUSED(lba_size);
    UNUSED(mdts_size);
    UNUSED(read);

    return ret;
}

int ss_nvme_device_read(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size) {
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(fd);
    UNUSED(nsid);
    UNUSED(slba);
    UNUSED(numbers);
    UNUSED(buffer);
    UNUSED(buf_size);
    
    return ret;
}

int ss_nvme_device_write(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size) {
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(fd);
    UNUSED(nsid);
    UNUSED(slba);
    UNUSED(numbers);
    UNUSED(buffer);
    UNUSED(buf_size);
    
    return ret;
}

int ss_zns_device_zone_reset(int fd, uint32_t nsid, uint64_t slba) {
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(fd);
    UNUSED(nsid);
    UNUSED(slba);
    
    return ret;
}

// this does not take slba because it will return that
int ss_zns_device_zone_append(int fd, uint32_t nsid, uint64_t zslba, int numbers, void *buffer, uint32_t buf_size, uint64_t *written_slba){
    //see section 4.5 how to write an append command
    int ret = -ENOSYS;
    // this is to supress gcc warnings, remove it when you complete this function 
    UNUSED(fd);
    UNUSED(nsid);
    UNUSED(zslba);
    UNUSED(numbers);
    UNUSED(buffer);
    UNUSED(buf_size);
    UNUSED(written_slba);

    return ret;
}

void update_lba(uint64_t &write_lba, const uint32_t lba_size, const int count){
    UNUSED(write_lba);
    UNUSED(lba_size);
    UNUSED(count);
    
}

// see 5.15.2.2 Identify Controller data structure (CNS 01h)
// see how to pass any number of variables in a C/C++ program https://stackoverflow.com/questions/1579719/variable-number-of-parameters-in-function-in-c
// feel free to pass any relevant function parameter to this function extract MDTS 
// you must return the MDTS as the return value of this function 
uint64_t get_mdts_size(int count, ...){    
    UNUSED(count);
    //FIXME 
    return 4096;
}

}