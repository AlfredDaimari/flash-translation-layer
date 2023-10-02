#include <asm-generic/errno.h>
#include <cstdint>
#include <fcntl.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <mutex>
#include <string.h>

#include "S2FileSystem.h"

std::unordered_map<uint32_t ,fd_info>fd_table;
uint32_t g_fd_count;    // always points to the next available fd
std::mutex fd_mut;
struct user_zns_device *g_my_dev;
struct fs_zns_device *fs_my_dev;

// init the file system
int fs_init(struct zdev_init_params *params){
        int ret = -ENOSYS; 
        uint64_t zns_num, tot_lba; 
        struct user_zns_device *my_dev;
        struct zns_dev_params *zns_dev;
        void * inode_bitmap_buf, * data_bitmap_buf;

        // init the zns device
        ret = init_ss_zns_device(params, &my_dev);
        g_my_dev = my_dev;

        // read persistent storage information
        

        // init zns device by pushing in bitmaps
        fs_my_dev = (struct fs_zns_device *) malloc(sizeof(struct fs_zns_device));

        // demarcating the device into i node blocks and data blocks
        zns_dev = my_dev->_private;
        
        zns_num = my_dev->tparams.zns_num_zones;    // number of zones;
       

        tot_lba = my_dev->capacity_bytes / my_dev->lba_size_bytes;

        uint64_t _t_x = tot_lba / 16;  // (magic number: divinding inode to data blocks in the ratio 1:15)

        fs_my_dev->total_inodes = _t_x;
        fs_my_dev->total_data_blocks = _t_x * 15;

        // now storing bit map data

        uint64_t inode_bmap_byte_size = _t_x;

        // aligning inode_bmap at lba size
        if (inode_bmap_byte_size % my_dev->lba_size_bytes != 0){
                if (inode_bmap_byte_size < my_dev->lba_size_bytes){
                        inode_bmap_byte_size = my_dev->lba_size_bytes;
                } else {
                        uint64_t padding = inode_bmap_byte_size % my_dev->lba_size_bytes;
                        padding = my_dev->lba_size_bytes - padding;
                        inode_bmap_byte_size += padding;
                }
        }
      
        
        inode_bitmap_buf = malloc(inode_bmap_byte_size);
        memset(inode_bitmap_buf, 0, inode_bmap_byte_size);

        // writing the bitmap to device
        ret = zns_udevice_write(my_dev, 0x00, inode_bitmap_buf, inode_bmap_byte_size);

        // writing the data bitmap
        fs_my_dev->data_bitmap_address = inode_bmap_byte_size;
        uint64_t data_bmap_byte_size = fs_my_dev->total_data_blocks;

        // aligning the data bitmap to one logical block
        if (data_bmap_byte_size % my_dev->lba_size_bytes != 0){
                if (data_bmap_byte_size < my_dev->lba_size_bytes){
                        data_bmap_byte_size = my_dev->lba_size_bytes;
                } else {
                        uint64_t padding = data_bmap_byte_size % my_dev->lba_size_bytes;
                        padding = my_dev->lba_size_bytes - padding;
                        data_bmap_byte_size += padding;
                }
        }
         
        data_bitmap_buf = malloc(data_bmap_byte_size);
        memset(data_bitmap_buf, 0, data_bmap_byte_size);
        ret = zns_udevice_write(data_bitmap_buf, fs_my_dev->data_bitmap_address, data_bmap_byte_size);

        // setting up data block address
        fs_my_dev->inode_address = fs_my_dev->data_bitmap_address + data_bmap_byte_size;
        // page size is a multipe of ar23_inode size
        fs_my_dev->data_address = fs_my_dev->inode_address + (sizeof(struct ar23_inode) * _t_x);
        // create first inode and make root directory

        return ret;
}

int fs_deinit(){
        int ret = -ENOSYS;
        
        // push unpushed metadata onto the device for persistent storage

        free(fs_my_dev);
        deinit_ss_zns_device(g_my_dev);

}

int ar23_open(char *filename, int oflag, mode_t mode){
        int ret = -ENOSYS;

        const uint32_t inode = ar23_get_inode(filename, oflag);

        if (inode == (uint32_t) -1){
                return ret;
        }
       
        {
                // preventing multiple threads from getting the same fd_num
                std::lock_guard<std::mutex> lock(fd_mut);
                const uint32_t rfd = g_fd_count;
                g_fd_count += 1;

                // insert
                fd_table.insert(std::make_pair(rfd, fd_info{rfd, inode, 0, mode}));
        }
        ret = 0;
        return ret;
}

int ar23_close(int fd){
        {
                std::lock_guard<std::mutex> lock(fd_mut);
                fd_table.erase(fd);
                
        }
}

// function will loop through the bitmap and get a free block

// increases the file size by expanding with one link data block and data block

int ar23_write(int fd, const void *buf, size_t size){
        // every write has to be from +8 bytes as there is metadata
        int ret = -ENOSYS;

        return ret;
}

// this may not be block allocated
uint64_t get_inode_address(uint64_t inode_id){
        return fs_my_dev->inode_address + (inode_id * sizeof(ar23_inode));
}

uint64_t get_inode_block_aligned_address(uint64_t inode_id){
        uint64_t inode_addr = get_inode_address(inode_id);
        uint64_t rem = inode_addr % my_dev->lba_size_bytes;
        return  inode_addr - rem; 
}

uint64_t get_inode_byte_offset_in_block(uint64_t inode_id){

        uint64_t inode_addr = get_inode_address(inode_id);
        uint64_t inode_block_al_addr = get_inode_block_aligned_address(inode_id);
        return inode_addr - inode_block_al_addr;
}

// inode read function

struct rd_sq_arr_ins{
        uint64_t address;
        uint64_t size;
};


// make contiguous read blocks using data sequence block
void get_contiguous_read_blocks(std::vector<uint64_t> data_sequence_arr, std::vector<rd_sq_arr_ins> &read_sequence_arr){ 

        // 63 index block points to sequence 
        for (int i = 0; i<63; i++){
                if (data_sequence_arr[i] == (uint64_t) -1){
                        break;
                } else {
                        int sz = read_sequence_arr.size();

                        if (sz == 0)
                                read_sequence_arr.push_back({data_sequence_arr[i], 4096});
                        else {
                                int lst_index = sz - 1;

                                // read blocks that contiguous in one zns call
                                if (read_sequence_arr[lst_index].address + read_sequence_arr[lst_index].size == data_sequence_arr[i]){
                                        read_sequence_arr[lst_index].size += 4096;
                                } else {
                                        // block are not contiguous, put in separate call
                                        read_sequence_arr.push_back({data_sequence_arr[i], 4096});
                                }
                        }
                }

        }
}

// reads data sequentially from the given starting address (the address has to be a link data block)
int read_data_from_address(uint64_t st_address, void *buf, uint64_t size){

        std::vector<uint64_t> data_sequence_arr(512, 0);
        std::vector<rd_sq_arr_ins> read_sequence_arr;

        uint32_t size_read;

        int ret = -ENOSYS;
        if (size == 0){
                return 0;
        }

        // reading the first link data sequence 
        ret = zns_udevice_read(data_sequence_arr.data(), st_address, my_dev->lba_size_bytes);

        // get contigous blocks in the data sequnce block
        get_contiguous_read_blocks(data_sequence_arr, read_sequence_arr);

        // read all data into the given buffer
        
        size_read = 0;
        for (int i = 0; i < read_sequence_arr.size(); i ++){
                uint8_t * t_buf = (uint8_t *) buf;
                t_buf += size_read; 
                ret = zns_udevice_read(my_dev, read_sequence_arr[i].address, t_buf, read_sequenc_arr[i].size);
                size_read += read_sequence_arr[i].size;
        }

        // check if data_sequence exists at the end of block
        if (data_sequence_arr[63] == (uint64_t) -1){
                int size_rem = size - size_read;
                uint8_t * t_buf = (uint8_t *) buf;
                t_buf += size_read;

                return read_data_from_address(data_sequence_arr[63], t_buf, size_rem)  // add further data to the buffer
        } 

        return ret;
}

// implemented without lseek  // perform errors checks with inode file size?
int ar23_read(int fd, const void *buf, size_t size){
        int ret = -ENOSYS;
        uint64_t inode, inode_address, data_block_st_addr;
        struct ar23_inode * inode_buf;

       
        struct fd_info temp = fd_table[fd];
        inode = temp.inode_number;

        inode_address = get_inode_address(inode);

        // getting the starting block for the inode reading inode metadata
        
        inode_buf = (struct ar23_inode *) malloc(sizeof(struct ar23_inode));
        lba_buf = malloc(my_dev->lba_size_bytes);
        ret = zns_udevice_read(lba_buf, inode_address, my_dev->lba_size_bytes);

        memcpy(inode_buf, lba_buf, sizeof(struct ar23_inode));

        data_block_st_addr = inode_buf->start_address;

        ret = read_data_from_address(data_block_st_addr, buf, size);

        return ret;
}
