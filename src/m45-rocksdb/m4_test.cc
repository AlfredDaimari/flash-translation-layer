// #include <cstdint>
// #include <iostream>
// #include <math.h>
// #include <mutex>
// #include <string>
// #include <sys/mman.h>
// #include <sys/types.h>
// #include <vector>
// #include <cstring>
// #include <random>
// #include "S2FileSystem.h"


// struct user_zns_device *g1_my_dev;
// struct fs_zns_device *fs1_my_dev;
// struct s2fs_inode *i1root;
// struct zdev_init_params params;


// void test_read_write(){
//         std::random_device rd;
//         std::mt19937 gen(rd());
//         std::uniform_int_distribution<uint8_t> dist(0, 255);

//         std::vector<uint8_t> vec;
//         for (uint i = 0; i < 4096 * 3; i++){
//                 vec.push_back(dist(gen));
//         }

//         int fd = s2fs_open("/file1", 0, 0);
//         s2fs_write(fd, vec.data(), 4096 * 3, 0);

//         std::vector<uint8_t> vec2(4096*3);
//         s2fs_read(fd, &vec2[3], 4096, 3);

//         for (uint i = 3; i < 4096 + 3; i++){
//                 if (vec[i] != vec2[i]){
//                         std::cout << "Error" << std::endl;
//                 }
//         }

//         // ow_write
//         s2fs_write(fd, &vec[3], 4096, 3);
//         s2fs_read(fd, &vec2[3], 4096, 3);

//         for (uint i = 3; i < 4096 + 3; i++){
//                 if (vec[i] != vec2[i]){
//                         std::cout << "Error" << std::endl;
//                 }
//         }

//         // test partial write

// }

// int main() {

//     int ret = -ENOSYS;
//   // make sure to setup these parameters properly and check the forced reset
//   // flag for M5
//   std::string device = "nvme0n1";
//   params.name = strdup (device.c_str ());
//   params.log_zones = 3;
//   params.gc_wmark = 1;
//   params.force_reset = false;
  
//   ret = init_ss_zns_device (&params, &g1_my_dev);
//   printf("Start sfs init \n");
//   ret = s2fs_init (g1_my_dev);
//   ret = s2fs_create_file("/dir1/dir3/file1", false);
//   ret = s2fs_create_file("/file1", false);
//     // // testing delete_dir
//   // std::cout << u << std::endl;
//   // // ret = s2fs_delete_dir("/dir2", true);

//   // bool v = s2fs_file_exists("/dir2");
//   // std::cout << v << std::endl;

//   // testing move_file
//   //ret = s2fs_move_file("/dir1/file4", "/dir2/file4");

//   //std::vector<std::string> children1;
//   //ret = s2fs_get_dir_children("/dir1", children1);
//   //std::cout << "Src: dir1\n" << std::endl;
//   //for (uint i = 0; i< children1.size(); i++){
//   //        std::cout << children1[i] << " ";
//   //}
//   //std::cout << std::endl << std::endl;
//   //std::vector<std::string> children;
//   //std::cout << "Dest: dir2\n" << std::endl;
//   //ret = s2fs_get_dir_children("/dir2", children);
//   //for (uint i = 0; i< children.size(); i++){
//   //       std::cout << children[i] << " ";
//   //}
  
//   test_read_write();

//   return ret;
// }

#include <memory>
#include <iostream>

#include "S2FileSystem.h"

namespace rdb = ROCKSDB_NAMESPACE;

int main() {
    rdb::S2FileSystem z ("s2fs:nvme0n1:///tmp/testdb/", true);
    std::unique_ptr<rdb::FSSequentialFile> file;
    z.CreateDirIfMissing("/a", rdb::IOOptions(), nullptr);
    z.CreateDir("/a", rdb::IOOptions(), nullptr);
    z.CreateDirIfMissing("/b", rdb::IOOptions(), nullptr);
    z.CreateDirIfMissing("/a/b", rdb::IOOptions(), nullptr);
    z.NewSequentialFile("/a/c", rdb::FileOptions(), &file, nullptr);

    std::vector<std::string> dirs1;
    z.GetChildren("/a", rdb::IOOptions(), &dirs1, nullptr);
    std::cout << "Children of /a are: " << std::endl;
    for (const auto &t: dirs1) {
        std::cout << "/a/" << t << std::endl;
    }

    z.RenameFile("/a/c", "/a/d", rdb::IOOptions(), nullptr);

    std::vector<std::string> dirs;
    z.GetChildren("/a", rdb::IOOptions(), &dirs, nullptr);
    std::cout << "Children of /a are: " << std::endl;
    for (const auto &t: dirs) {
        std::cout << "/a/" << t << std::endl;
    }



    std::unique_ptr<rdb::FSWritableFile> wr_file;
    if (!z.NewWritableFile("/a/c", rdb::FileOptions(), &wr_file, nullptr).ok()) {
        std::cout << "Could not create writeable file" << std::endl;
    }

    auto const num_action = 58344;

    std::vector<uint8_t> buffer;
    for (uint32_t i = 0; i < num_action; i++) {
        buffer.push_back(i % 0xFF);
    }

    auto s = rdb::Slice((char*)&buffer[0], num_action);
    if (!wr_file->Append(s, rdb::IOOptions(), nullptr).ok())
    std::cout << "Append fucking up" << std::endl;
    if (!wr_file->Close(rdb::IOOptions(), nullptr).ok())
    std::cout << "Close fucking up" << std::endl;

    

    std::vector<char> temp_buffer;
    temp_buffer.resize(num_action);
    z.NewSequentialFile("/a/c", rdb::FileOptions(), &file, nullptr);

    rdb::Slice slice;
    if (!file->Read(num_action, rdb::IOOptions(), &slice, &temp_buffer[0], nullptr).ok()) {
        std::cout << "Could not read" << std::endl;
    }

    for (uint32_t i = 0; i < num_action; i++) {
        if ((uint8_t)*(slice.data() + i) != (uint8_t)(i % 0xFF)) {
            std::cout << "Not matching " << std::to_string(i) << " " << std::to_string((uint8_t)*(slice.data() + i)) << " " << std::to_string(i % 0xFF) << std::endl;
        }
    }

    std::unique_ptr<rdb::FSRandomAccessFile> r_file;
    z.NewRandomAccessFile("/a/c", rdb::FileOptions(), &r_file, nullptr);
    r_file->Read(255, 128, rdb::IOOptions(), &slice, &temp_buffer[0], nullptr);
    for (uint32_t i = 0; i < 128; i++) {
        if ((uint8_t)*(slice.data() + i) != (uint8_t)i) {
            std::cout << "Not matching " << std::to_string(i) << " " << std::to_string((uint8_t)*(slice.data() + i)) << " " << std::to_string(i) << std::endl;
        }
    }

    z.DeleteDir("/a", rdb::IOOptions(), nullptr);
    dirs.clear();
    z.GetChildren("/", rdb::IOOptions(), &dirs, nullptr);
    std::cout << "Children of / are: " << std::endl;
    for (const auto &t: dirs) {
        std::cout << "/" << t << std::endl;
    }

    std::cout << "All done!" << std::endl;

    return 0;
}

