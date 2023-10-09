#include <cstdint>
#include <iostream>
#include <math.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <vector>
#include <cstring>



#include "s2fs_test.h"


struct user_zns_device *g1_my_dev;
struct fs_zns_device *fs1_my_dev;
struct s2fs_inode *i1root;
struct zdev_init_params params;
int main() {

    int ret = -ENOSYS;
  // make sure to setup these parameters properly and check the forced reset
  // flag for M5
  std::string device = "nvme0n1";
  params.name = strdup (device.c_str ());
  params.log_zones = 3;
  params.gc_wmark = 1;
  params.force_reset = false;
  
  ret = init_ss_zns_device (&params, &g1_my_dev);
  printf("Start sfs init \n");
  ret = s2fs_init (g1_my_dev);
  ret = s2fs_create_file("/file1", 0);
  return ret;
}


