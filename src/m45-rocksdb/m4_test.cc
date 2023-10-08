#include <cstdint>
#include <iostream>
#include <math.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <vector>



#include "S2FileSystem.h"


struct user_zns_device *g_my_dev;
struct fs_zns_device *fs_my_dev;
struct s2fs_inode *iroot;
struct zdev_init_params *params;

int main() {

    int ret = -ENOSYS;

    ret = init_ss_zns_device(params, &g_my_dev);

    ret = s2fs_init (g_my_dev);

    printf("Here");    

    return ret;

}


