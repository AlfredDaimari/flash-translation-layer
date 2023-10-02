#include <asm-generic/errno.h>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <mutex>
#include <string.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "S2FileSystem.h"
#include <zns_device.h>

std::unordered_map<uint32_t, fd_info> fd_table;
uint32_t g_fd_count; // always points to the next available fd
std::mutex fd_mut;
struct user_zns_device *g_my_dev;
struct fs_zns_device *fs_my_dev;

// init the file system
int
fs_init (struct zdev_init_params *params)
{
  int ret = -ENOSYS;
  uint64_t zns_num, tot_lba;
  struct user_zns_device *my_dev;
  struct zns_dev_params *zns_dev;
  void *inode_bitmap_buf, *data_bitmap_buf;

  // init the zns device
  ret = init_ss_zns_device (params, &my_dev);
  g_my_dev = my_dev;

  // read persistent storage information

  // init zns device by pushing in bitmaps
  fs_my_dev = (struct fs_zns_device *)malloc (sizeof (struct fs_zns_device));

  // demarcating the device into i node blocks and data blocks
  zns_dev = (struct zns_dev_params *)my_dev->_private;

  zns_num = my_dev->tparams.zns_num_zones; // number of zones;

  tot_lba = my_dev->capacity_bytes / my_dev->lba_size_bytes;

  uint64_t _t_x = tot_lba / 16; // (magic number: divinding inode to data
                                // blocks in the ratio 1:15)

  fs_my_dev->total_inodes = _t_x;
  fs_my_dev->total_data_blocks = _t_x * 15;

  // now storing bit map data

  uint64_t inode_bmap_bit_size = _t_x;

  // converting inode_bmap_bit_size into bytes size
  uint64_t pad_bits = inode_bmap_bit_size % 8;
  uint64_t inode_bmap_byte_size = (inode_bmap_bit_size + pad_bits) / 8;

  // aligning inode_bmap at lba size
  if (inode_bmap_byte_size % my_dev->lba_size_bytes != 0)
    {
      if (inode_bmap_byte_size < my_dev->lba_size_bytes)
        {
          inode_bmap_byte_size = my_dev->lba_size_bytes;
        }
      else
        {
          uint64_t padding = inode_bmap_byte_size % my_dev->lba_size_bytes;
          padding = my_dev->lba_size_bytes - padding;
          inode_bmap_byte_size += padding;
        }
    }

  inode_bitmap_buf = malloc (inode_bmap_byte_size);
  memset (inode_bitmap_buf, 0, inode_bmap_byte_size);

  // writing the bitmap to device
  ret = zns_udevice_write (my_dev, 0x00, inode_bitmap_buf,
                           inode_bmap_byte_size);

  // writing the data bitmap
  fs_my_dev->data_bitmap_address = inode_bmap_byte_size;
  uint64_t data_bmap_byte_size = fs_my_dev->total_data_blocks;

  // aligning the data bitmap to one logical block
  if (data_bmap_byte_size % my_dev->lba_size_bytes != 0)
    {
      if (data_bmap_byte_size < my_dev->lba_size_bytes)
        {
          data_bmap_byte_size = my_dev->lba_size_bytes;
        }
      else
        {
          uint64_t padding = data_bmap_byte_size % my_dev->lba_size_bytes;
          padding = my_dev->lba_size_bytes - padding;
          data_bmap_byte_size += padding;
        }
    }

  data_bitmap_buf
      = malloc (data_bmap_byte_size); // may not work for large sizes
  memset (data_bitmap_buf, 0, data_bmap_byte_size);
  ret = zns_udevice_write (my_dev, fs_my_dev->data_bitmap_address,
                           data_bitmap_buf, data_bmap_byte_size);

  // setting up data block address
  fs_my_dev->inode_address
      = fs_my_dev->data_bitmap_address + data_bmap_byte_size;
  // page size is a multipe of ar23_inode size
  fs_my_dev->data_address
      = fs_my_dev->inode_address + (sizeof (struct ar23_inode) * _t_x);
  // create first inode and make root directory

  return ret;
}

int
fs_deinit ()
{
  int ret = -ENOSYS;

  // push unpushed metadata onto the device for persistent storage

  free (fs_my_dev);
  ret = deinit_ss_zns_device (g_my_dev);
  return ret;
}

// this may not be block allocated
uint64_t
get_inode_address (uint64_t inode_id)
{
  return fs_my_dev->inode_address + (inode_id * sizeof (ar23_inode));
}

uint64_t
get_inode_block_aligned_address (uint64_t inode_id)
{
  uint64_t inode_addr = get_inode_address (inode_id);
  uint64_t rem = inode_addr % g_my_dev->lba_size_bytes;
  return inode_addr - rem;
}

uint64_t
get_inode_byte_offset_in_block (uint64_t inode_id)
{

  uint64_t inode_addr = get_inode_address (inode_id);
  uint64_t inode_block_al_addr = get_inode_block_aligned_address (inode_id);
  return inode_addr - inode_block_al_addr;
}

// make contiguous logical read blocks using data link block
void
get_contiguous_read_blocks (std::vector<data_lnb_row> data_lnb_arr,
                            std::vector<data_lnb_row> &zns_lb_read_arr)
{

  int t_rows = (g_my_dev->lba_size_bytes / sizeof (data_lnb_row))
               - 1; // last row is data link row
  for (int i = 0; i < t_rows; i++)
    {
      // using max possible address to denote end of list
      if (data_lnb_arr[i].address == (uint64_t)-1)
        {
          break;
        }
      else
        {
          int sz = zns_lb_read_arr.size ();

          if (sz == 0)
            zns_lb_read_arr.push_back ({ zns_lb_read_arr[i].address, 4096 });

          else
            {
              int lst_index = sz - 1;

              // read blocks that contiguous in one zns call
              if (zns_lb_read_arr[lst_index].address
                      + zns_lb_read_arr[lst_index].size
                  == data_lnb_arr[i].address)
                {
                  zns_lb_read_arr[lst_index].size += 4096;
                }
              else
                {
                  // block are not contiguous, put in separate call
                  zns_lb_read_arr.push_back (
                      { data_lnb_arr[i].address, 4096 });
                }
            }
        }
    }
}

// reads data sequentially from the given starting address (the address has to
// be a link data block)
int
read_data_from_address (uint64_t st_address, void *buf, size_t size)
{

  int t_rows = g_my_dev->lba_size_bytes / sizeof (struct data_lnb_row);
  std::vector<data_lnb_row> data_lnb_arr (t_rows);
  std::vector<data_lnb_row> zns_lb_read_arr;

  uint32_t size_read;

  int ret = -ENOSYS;
  if (size == 0)
    {
      return 0;
    }

  // reading the first link data sequence
  ret = zns_udevice_read (g_my_dev, st_address, data_lnb_arr.data (),
                          g_my_dev->lba_size_bytes);

  // get contigous blocks in the data sequnce block
  get_contiguous_read_blocks (data_lnb_arr, zns_lb_read_arr);

  // read all data into the given buffer

  size_read = 0;
  for (uint i = 0; i < zns_lb_read_arr.size (); i++)
    {
      uint8_t *t_buf = (uint8_t *)buf;
      t_buf += size_read;
      ret = zns_udevice_read (g_my_dev, zns_lb_read_arr[i].address, t_buf,
                              zns_lb_read_arr[i].size);
      size_read += zns_lb_read_arr[i].size;
    }

  // check if data_sequence exists at the end of block
  if (data_lnb_arr[t_rows - 1].address == (uint64_t)-1)
    {
      int size_rem = size - size_read;
      uint8_t *t_buf = (uint8_t *)buf;
      t_buf += size_read;

      return read_data_from_address (
          data_lnb_arr[t_rows - 1].address, t_buf,
          size_rem); // add further data to the buffer
    }

  return ret;
}

// given free_block_list should be in ascending order
void
get_contiguous_write_blocks (std::vector<uint64_t> free_block_list,
                             std::vector<data_lnb_row> &zns_lb_write_arr)
{
  for (uint i = 0; i < free_block_list.size (); i++)
    {
      int sz = zns_lb_write_arr.size ();

      if (sz == 0)
        zns_lb_write_arr.push_back ({ free_block_list[i], 4096 });

      else
        {
          int lst_index = sz - 1;

          // read blocks that contiguous in one zns call
          if (zns_lb_write_arr[lst_index].address
                  + zns_lb_write_arr[lst_index].size
              == free_block_list[i])
            {
              zns_lb_write_arr[lst_index].size += 4096;
            }
          else
            {
              // block are not contiguous, put in separate call
              zns_lb_write_arr.push_back ({ free_block_list[i], 4096 });
            }
        }
    }
}

// insert the data block addresses into the data block link address
int
insert_db_addr_in_dlb (uint64_t dlb_address,
                       std::vector<uint64_t> free_block_list, size_t size)
{
  int ret = -ENOSYS;

  // getting the first free data block row in the dlb
  uint t_rows = g_my_dev->lba_size_bytes / sizeof (struct data_lnb_row);
  std::vector<data_lnb_row> data_lnb_arr (t_rows);
  ret = zns_udevice_read (g_my_dev, dlb_address, data_lnb_arr.data (),
                          g_my_dev->lba_size_bytes);
  uint uf_lb = t_rows - 1;
  uint t_size = size;
  for (uint i = 0; i < data_lnb_arr.size (); i++)
    {
      if (data_lnb_arr[i].address == (uint)-1)
        {
          uf_lb = i;
          break;
        }
    }

  for (uint i = uf_lb; i < data_lnb_arr.size (); i++)
    {
      uint b_size = g_my_dev->lba_size_bytes < t_size
                        ? g_my_dev->lba_size_bytes
                        : t_size;
      data_lnb_arr[i] = { free_block_list[0], b_size };

      t_size -= b_size;

      // remove the first link from free list
      free_block_list.erase (free_block_list.begin ());

      if (free_block_list.size () == 0)
        {
          break;
        }
    }

  // when current data link block is full but free list has entries
  if (free_block_list.size () != 0)
    {

      uint64_t free_dlb_addr = get_free_link_data_block ();

      // insert link block where free blocks will be inserted
      data_lnb_arr[t_rows - 1].address = free_dlb_addr;
      // write updated link data block
      ret = zns_udevice_write (g_my_dev, dlb_address, data_lnb_arr.data (),
                               g_my_dev->lba_size_bytes);
      ret = insert_db_addr_in_dlb (free_dlb_addr, free_block_list, t_size);
    }
  else
    {
      ret = zns_udevice_write (g_my_dev, dlb_address, data_lnb_arr.data (),
                               g_my_dev->lba_size_bytes);
    }

  return ret;
}

int
write_to_free_data_blocks (void *buf, uint64_t size, uint64_t cur_dlb)
{
  int ret = -ENOSYS;
  std::vector<uint64_t> free_block_list;
  std::vector<data_lnb_row> zns_lb_write_arr;

  ret = get_free_data_blocks (size, free_block_list);
  get_contiguous_write_blocks (free_block_list, zns_lb_write_arr);
  uint tmp_size = size;
  uint8_t *t_buf = (uint8_t *)buf;

  // writing to all free blocks
  for (uint i = 0; i < zns_lb_write_arr.size (); i++)
    {

      int b_size = zns_lb_write_arr[i].size <= tmp_size
                       ? zns_lb_write_arr[i].size
                       : tmp_size;
      // aligning with lba size bytes
      void *w_buf = malloc (zns_lb_write_arr[i].size);
      mempcpy (w_buf, t_buf, b_size);

      ret = zns_udevice_write (g_my_dev, zns_lb_write_arr[i].address, w_buf,
                               zns_lb_write_arr[i].size);
      t_buf += b_size;
      tmp_size -= b_size;
    }

  insert_db_addr_in_dlb (cur_dlb, free_block_list,
                         size); // insert all the currently newly written
                                // blocks into the data link block

  return ret;
}

// will work for append files and write new files
int
write_data_from_address (uint64_t st_address, void *buf, size_t size)
{
  int ret = -ENOSYS;
  uint t_rows = g_my_dev->lba_size_bytes / sizeof (struct data_lnb_row);
  uint uf_bln = t_rows - 1;
  std::vector<data_lnb_row> data_lnb_arr (t_rows);
  std::vector<uint64_t> free_block_list;

  // get the first partially filled block
  ret = zns_udevice_read (g_my_dev, st_address, data_lnb_arr.data (),
                          g_my_dev->lba_size_bytes);

  for (uint i = 0; i < t_rows; i++)
    {
      // when there is a half filled block
      if (data_lnb_arr[i].size != 0
          && data_lnb_arr[i].size < g_my_dev->lba_size_bytes)
        {
          uf_bln = i;
          break;
        }

      // when there is an unfilled block
      if (data_lnb_arr[i].size == 0 && data_lnb_arr[i].address == (uint)-1)
        {
          uf_bln = i;
          break;
        }
    }

  // when uf_bln is partially filled block
  if (data_lnb_arr[uf_bln].size < g_my_dev->lba_size_bytes
      && data_lnb_arr[uf_bln].size > 0)
    {
      uint rem_free_bytes
          = g_my_dev->lba_size_bytes - data_lnb_arr[uf_bln].size;

      // write the rem_free_bytes to the block
      void *fl_buf = malloc (g_my_dev->lba_size_bytes);
      ret = zns_udevice_read (g_my_dev, data_lnb_arr[uf_bln].address, fl_buf,
                              g_my_dev->lba_size_bytes);

      uint8_t *t_fl_buf = ((uint8_t *)fl_buf) + data_lnb_arr[uf_bln].size;
      memcpy (t_fl_buf, buf, rem_free_bytes);

      // write the full buf back to the logical block
      ret = zns_udevice_write (g_my_dev, data_lnb_arr[uf_bln].address, fl_buf,
                               g_my_dev->lba_size_bytes);

      t_fl_buf = ((uint8_t *)buf) + rem_free_bytes;

      write_to_free_data_blocks (t_fl_buf, size - rem_free_bytes, st_address);
    }

  // when uf_bln is unfilled and is not the last link row
  else if (data_lnb_arr[uf_bln].size == 0 && uf_bln != t_rows - 1)
    {
      // write to free data blocks
      ret = write_to_free_data_blocks (buf, size, st_address);

      // when uf_bln is the last link row
    }
  else
    {
      // check if dlb at last index is initialized or not
      if (data_lnb_arr[uf_bln].address == (uint)-1)
        {
          data_lnb_arr[uf_bln].address = get_free_link_data_block ();

          // write the updated data_lnb_buff to device
          ret = zns_udevice_write (g_my_dev, data_lnb_arr[uf_bln].address,
                                   data_lnb_arr.data (),
                                   g_my_dev->lba_size_bytes);

          ret = write_data_from_address (data_lnb_arr[uf_bln].address, buf,
                                         size);
        }
      else
        {
          ret = write_data_from_address (data_lnb_arr[uf_bln].address, buf,
                                         size);
        }
    }
  return ret;
}

int
ar23_open (char *filename, int oflag, mode_t mode)
{
  int ret = -ENOSYS;

  const uint32_t inode = ar23_get_inode (filename, oflag);

  if (inode == (uint32_t)-1)
    {
      return ret;
    }

  {
    // preventing multiple threads from getting the same fd_num
    std::lock_guard<std::mutex> lock (fd_mut);
    const uint32_t rfd = g_fd_count;
    g_fd_count += 1;

    // insert
    fd_table.insert (std::make_pair (rfd, fd_info{ rfd, inode, 0, mode }));
  }
  ret = 0;
  return ret;
}

int
ar23_close (int fd)
{
  {
    std::lock_guard<std::mutex> lock (fd_mut);
    fd_table.erase (fd);
  }

  return 0;
}

// function will loop through the bitmap and get a free block

// increases the file size by expanding with one link data block and data block

int
ar23_write (int fd, const void *buf, size_t size)
{
  // every write has to be from +8 bytes as there is metadata
  int ret = -ENOSYS;

  return ret;
}

// implemented without lseek  // perform errors checks with inode file size?
int
ar23_read (int fd, const void *buf, size_t size)
{
  int ret = -ENOSYS;
  uint64_t inode, inode_address, data_block_st_addr;
  struct ar23_inode *inode_buf;

  struct fd_info temp = fd_table[fd];
  inode = temp.inode_number;

  inode_address = get_inode_address (inode);

  // getting the starting block for the inode reading inode metadata

  inode_buf = (struct ar23_inode *)malloc (sizeof (struct ar23_inode));
  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_address, lba_buf,
                          g_my_dev->lba_size_bytes);

  memcpy (inode_buf, lba_buf, sizeof (struct ar23_inode));

  data_block_st_addr = inode_buf->start_address;

  ret = read_data_from_address (data_block_st_addr, (void *)buf, size);
  return ret;
}
