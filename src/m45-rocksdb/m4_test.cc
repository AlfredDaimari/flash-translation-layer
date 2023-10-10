#include <cstdint>
#include <iostream>
#include <math.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <vector>
#include <cstring>
#include <random>
#include "S2FileSystem.h"


struct user_zns_device *g1_my_dev;
struct fs_zns_device *fs1_my_dev;
struct s2fs_inode *i1root;
struct zdev_init_params params;


void test_read_write(){
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        std::vector<uint8_t> vec;
        for (uint i = 0; i < 4096 * 3; i++){
                vec.push_back(dist(gen));
        }

        int fd = s2fs_open("/file1", 0, 0);
        s2fs_write(fd, vec.data(), 4096 * 3, 0);

        std::vector<uint8_t> vec2(4096*3);
        s2fs_read(fd, &vec2[3], 4096, 3);

        for (uint i = 3; i < 4096 + 3; i++){
                if (vec[i] != vec2[i]){
                        std::cout << "Error" << std::endl;
                }
        }
}

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
  ret = s2fs_create_file("/file1", false);
  ret = s2fs_create_file("/file3", false);
  ret = s2fs_create_file("/dir1", true);
  ret = s2fs_create_file("/dir1/file4", false);
  ret = s2fs_create_file("/dir1/file5", false);
  ret = s2fs_create_file("/file6", false);
  ret = s2fs_delete_file("/file3");
  ret = s2fs_create_file("/dir2", true); 
  
  // // testing delete_dir
  // std::cout << u << std::endl;
  // // ret = s2fs_delete_dir("/dir2", true);

  // bool v = s2fs_file_exists("/dir2");
  // std::cout << v << std::endl;

  // testing move_file
  //ret = s2fs_move_file("/dir1/file4", "/dir2/file4");

  //std::vector<std::string> children1;
  //ret = s2fs_get_dir_children("/dir1", children1);
  //std::cout << "Src: dir1\n" << std::endl;
  //for (uint i = 0; i< children1.size(); i++){
  //        std::cout << children1[i] << " ";
  //}
  //std::cout << std::endl << std::endl;
  //std::vector<std::string> children;
  //std::cout << "Dest: dir2\n" << std::endl;
  //ret = s2fs_get_dir_children("/dir2", children);
  //for (uint i = 0; i< children.size(); i++){
  //       std::cout << children[i] << " ";
  //}
  
  test_read_write();

  return ret;
}


