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

#include "S2FileSystem.h"
#include <iostream>
#include <string>
#include <sys/mman.h>

#include <stosys_debug.h>
#include <utils.h>

/* Things to implement
 *
 * GetAbsolutePath
 * CreateDirIfMissing
 * FileExists
 * RenameFile
 * NewLogger
 * GetChildren
 * GetFileSize
 * NewDirectory
 * LockFile
 * NewRandomAccessFile
 * NewSequentialFile
 * NewWritableFile
 * DeleteFile
 */

namespace ROCKSDB_NAMESPACE
{
S2FileSystem::S2FileSystem (std::string uri_db_path, bool debug)
{
  FileSystem::Default ();
  std::string sdelimiter = ":";
  std::string edelimiter = "://";
  this->_uri = uri_db_path;
  struct zdev_init_params params;
  std::string device = uri_db_path.substr (
      uri_db_path.find (sdelimiter) + sdelimiter.size (),
      uri_db_path.find (edelimiter)
          - (uri_db_path.find (sdelimiter) + sdelimiter.size ()));
  // make sure to setup these parameters properly and check the forced reset
  // flag for M5
  params.name = strdup (device.c_str ());
  params.log_zones = 3;
  params.gc_wmark = 1;
  params.force_reset = false;
  int ret = init_ss_zns_device (&params, &this->_zns_dev);
  if (ret != 0)
    {
      std::cout << "Error: " << uri_db_path << " failed to open the device "
                << device.c_str () << "\n";
      std::cout << "Error: ret " << ret << "\n";
    }
  assert (ret == 0);
  assert (this->_zns_dev->lba_size_bytes != 0);
  assert (this->_zns_dev->capacity_bytes != 0);
  ss_dprintf (DBG_FS_1,
              "device %s is opened and initialized, reported LBA size is %u "
              "and capacity %lu \n",
              device.c_str (), this->_zns_dev->lba_size_bytes,
              this->_zns_dev->capacity_bytes);
}

S2FileSystem::~S2FileSystem () {}

// Create a brand new sequentially-readable file with the specified name.
// On success, stores a pointer to the new file in *result and returns OK.
// On failure stores nullptr in *result and returns non-OK.  If the file does
// not exist, returns a non-OK status.
//
// The returned file will only be accessed by one thread at a time.
IOStatus
S2FileSystem::NewSequentialFile (const std::string &fname,
                                 const FileOptions &file_opts,
                                 std::unique_ptr<FSSequentialFile> *result,
                                 __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::IsDirectory (const std::string &, const IOOptions &options,
                           bool *is_dir, IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

// Create a brand new random access read-only file with the
// specified name.  On success, stores a pointer to the new file in
// *result and returns OK.  On failure stores nullptr in *result and
// returns non-OK.  If the file does not exist, returns a non-OK
// status.
//
// The returned file may be concurrently accessed by multiple threads.
IOStatus
S2FileSystem::NewRandomAccessFile (const std::string &fname,
                                   const FileOptions &file_opts,
                                   std::unique_ptr<FSRandomAccessFile> *result,
                                   __attribute__ ((unused))
                                   IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

const char *
S2FileSystem::Name () const
{
  return "S2FileSytem";
}

// Create an object that writes to a new file with the specified
// name.  Deletes any existing file with the same name and creates a
// new file.  On success, stores a pointer to the new file in
// *result and returns OK.  On failure stores nullptr in *result and
// returns non-OK.
//
// The returned file will only be accessed by one thread at a time.
IOStatus
S2FileSystem::NewWritableFile (const std::string &fname,
                               const FileOptions &file_opts,
                               std::unique_ptr<FSWritableFile> *result,
                               __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::ReopenWritableFile (const std::string &, const FileOptions &,
                                  std::unique_ptr<FSWritableFile> *,
                                  IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::NewRandomRWFile (const std::string &, const FileOptions &,
                               std::unique_ptr<FSRandomRWFile> *,
                               IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::NewMemoryMappedFileBuffer (
    const std::string &, std::unique_ptr<MemoryMappedFileBuffer> *)
{
  return IOStatus::IOError (__FUNCTION__);
}

// Create an object that represents a directory. Will fail if directory
// doesn't exist. If the directory exists, it will open the directory
// and create a new Directory object.
//
// On success, stores a pointer to the new Directory in
// *result and returns OK. On failure stores nullptr in *result and
// returns non-OK.
IOStatus
S2FileSystem::NewDirectory (const std::string &name, const IOOptions &io_opts,
                            std::unique_ptr<FSDirectory> *result,
                            __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::GetFreeSpace (const std::string &, const IOOptions &, uint64_t *,
                            IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::Truncate (const std::string &, size_t, const IOOptions &,
                        IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

// Create the specified directory. Returns error if directory exists.
IOStatus
S2FileSystem::CreateDir (const std::string &dirname, const IOOptions &options,
                         __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

// Creates directory if missing. Return Ok if it exists, or successful in
// Creating.
IOStatus
S2FileSystem::CreateDirIfMissing (const std::string &dirname,
                                  const IOOptions &options,
                                  __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::GetFileSize (const std::string &fname, const IOOptions &options,
                           uint64_t *file_size,
                           __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::DeleteDir (const std::string &dirname, const IOOptions &options,
                         __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::GetFileModificationTime (const std::string &fname,
                                       const IOOptions &options,
                                       uint64_t *file_mtime,
                                       __attribute__ ((unused))
                                       IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::GetAbsolutePath (const std::string &db_path,
                               const IOOptions &options,
                               std::string *output_path,
                               __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::DeleteFile (const std::string &fname, const IOOptions &options,
                          __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::NewLogger (const std::string &fname, const IOOptions &io_opts,
                         std::shared_ptr<Logger> *result,
                         __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::GetTestDirectory (const IOOptions &options, std::string *path,
                                __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

// Release the lock acquired by a previous successful call to LockFile.
// REQUIRES: lock was returned by a successful LockFile() call
// REQUIRES: lock has not already been unlocked.
IOStatus
S2FileSystem::UnlockFile (FileLock *lock, const IOOptions &options,
                          __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

// Lock the specified file.  Used to prevent concurrent access to
// the same db by multiple processes.  On failure, stores nullptr in
// *lock and returns non-OK.
//
// On success, stores a pointer to the object that represents the
// acquired lock in *lock and returns OK.  The caller should call
// UnlockFile(*lock) to release the lock.  If the process exits,
// the lock will be automatically released.
//
// If somebody else already holds the lock, finishes immediately
// with a failure.  I.e., this call does not wait for existing locks
// to go away.
//
// May create the named file if it does not already exist.
IOStatus
S2FileSystem::LockFile (const std::string &fname, const IOOptions &options,
                        FileLock **lock,
                        __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::AreFilesSame (const std::string &, const std::string &,
                            const IOOptions &, bool *, IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::NumFileLinks (const std::string &, const IOOptions &, uint64_t *,
                            IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::LinkFile (const std::string &, const std::string &,
                        const IOOptions &, IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::RenameFile (const std::string &src, const std::string &target,
                          const IOOptions &options,
                          __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::GetChildrenFileAttributes (const std::string &dir,
                                         const IOOptions &options,
                                         std::vector<FileAttributes> *result,
                                         __attribute__ ((unused))
                                         IODebugContext *dbg)
{
  return FileSystem::GetChildrenFileAttributes (dir, options, result, dbg);
}

// Store in *result the names of the children of the specified directory.
// The names are relative to "dir".
// Original contents of *results are dropped.
// Returns OK if "dir" exists and "*result" contains its children.
//         NotFound if "dir" does not exist, the calling process does not have
//                  permission to access "dir", or if "dir" is invalid.
//         IOError if an IO Error was encountered
IOStatus
S2FileSystem::GetChildren (const std::string &dir, const IOOptions &options,
                           std::vector<std::string> *result,
                           __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

// Returns OK if the named file exists.
//         NotFound if the named file does not exist,
//                  the calling process does not have permission to determine
//                  whether this file exists, or if the path is invalid.
//         IOError if an IO Error was encountered
IOStatus
S2FileSystem::FileExists (const std::string &fname, const IOOptions &options,
                          __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}

IOStatus
S2FileSystem::ReuseWritableFile (const std::string &fname,
                                 const std::string &old_fname,
                                 const FileOptions &file_opts,
                                 std::unique_ptr<FSWritableFile> *result,
                                 __attribute__ ((unused)) IODebugContext *dbg)
{
  return IOStatus::IOError (__FUNCTION__);
}
}

std::unordered_map<uint32_t, fd_info> fd_table;
// holds information whether the file is being written to or not
uint32_t g_fd_count; // always points to the next available fd
std::mutex fd_mut;
std::mutex bitmap_mut; // mutex for when making changes to the bitmap
struct user_zns_device *g_my_dev;
struct fs_zns_device *fs_my_dev;
Inode iroot;

// init the file system
int
fs_init (struct user_zns_device *my_dev)
{
  int ret = -ENOSYS;
  uint64_t zns_num, tot_lba;
  struct zns_dev_params *zns_dev;
  void *inode_bitmap_buf, *data_bitmap_buf;

  // init the zns device
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
  uint64_t data_bmap_bit_size = fs_my_dev->total_data_blocks;
  pad_bits = data_bmap_bit_size % 8;

  uint64_t data_bmap_byte_size = (data_bmap_bit_size + pad_bits) / 8;

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

  free (inode_bitmap_buf);
  free (data_bitmap_buf);

  return ret;
}

int
fs_deinit ()
{
  // push unpushed metadata onto the device for persistent storage

  free (fs_my_dev);
  return 0;
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

// is logical block aligned always
uint64_t
get_dblock_address (uint64_t dblock_id)
{
  return fs_my_dev->data_address + (dblock_id * g_my_dev->lba_size_bytes);
}

int
read_data_bitmap (std::vector<bool> **data_bitmap)
{
  uint64_t st_address = fs_my_dev->data_bitmap_address;

  uint64_t data_bmap_bit_size = fs_my_dev->total_data_blocks;
  uint64_t pad_bits = data_bmap_bit_size % 8;

  uint32_t data_bmap_byte_size = (data_bmap_bit_size + pad_bits) / 8;

  // aligning the data bitmap to logical block size
  if (data_bmap_byte_size % g_my_dev->lba_size_bytes != 0)
    {
      if (data_bmap_byte_size < g_my_dev->lba_size_bytes)
        {
          data_bmap_byte_size = g_my_dev->lba_size_bytes;
        }
      else
        {
          uint64_t padding = data_bmap_byte_size % g_my_dev->lba_size_bytes;
          padding = g_my_dev->lba_size_bytes - padding;
          data_bmap_byte_size += padding;
        }
    }

  *data_bitmap = new std::vector<bool> (data_bmap_byte_size);

  int ret = zns_udevice_read (g_my_dev, st_address, *data_bitmap,
                              data_bmap_byte_size);

  return ret;
}

int
write_data_bitmap (void *data_bitmap_buf)
{
  uint64_t st_address = fs_my_dev->data_bitmap_address;

  uint64_t data_bmap_bit_size = fs_my_dev->total_data_blocks;
  uint64_t pad_bits = data_bmap_bit_size % 8;

  uint32_t data_bmap_byte_size = (data_bmap_bit_size + pad_bits) / 8;

  // aligning the data bitmap to logical block size
  if (data_bmap_byte_size % g_my_dev->lba_size_bytes != 0)
    {
      if (data_bmap_byte_size < g_my_dev->lba_size_bytes)
        {
          data_bmap_byte_size = g_my_dev->lba_size_bytes;
        }
      else
        {
          uint64_t padding = data_bmap_byte_size % g_my_dev->lba_size_bytes;
          padding = g_my_dev->lba_size_bytes - padding;
          data_bmap_byte_size += padding;
        }
    }

  int ret = zns_udevice_write (g_my_dev, st_address, data_bitmap_buf,
                               data_bmap_byte_size);

  return ret;
}

int
get_free_data_blocks (uint64_t size, std::vector<uint64_t> &free_block_list)
{
  int ret = -ENOSYS;
  {
    std::lock_guard<std::mutex> lock (bitmap_mut);

    // read datablock bitmap
    std::vector<bool> *data_bitmap;
    std::vector<uint64_t> free_db_id_list;

    uint32_t total_blocks_to_alloc
        = size / g_my_dev->lba_size_bytes
          + (size % g_my_dev->lba_size_bytes > 0 ? 1 : 0);

    read_data_bitmap (&data_bitmap);

    for (uint i = 0; i < (*data_bitmap).size (); i++)
      {
        if ((*data_bitmap)[i] == false)
          {
            free_db_id_list.push_back (i);
          }
      }

    // when not enough data blocks
    if (total_blocks_to_alloc != free_db_id_list.size ())
      {
        ret = -1;
      }
    else
      {
        for (uint i = 0; i < free_db_id_list.size (); i++)
          (*data_bitmap)[free_db_id_list[i]] = true;

        // write data_bitmap back
        write_data_bitmap (data_bitmap);
        free (data_bitmap);
        ret = 0;
      }
  }
  return ret;
};

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
                  // block are not contiguous, put in separate read call
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

/* gets all the data block addresses associated with a file
 *
 * st_dblock_addr <- starting data link block for the inode
 * inode_db_addr_list <- vector where to insert all the data block addresses
 * for an inode
 *
 */
void
get_all_inode_data_links (uint64_t st_dblock_addr,
                          std::vector<data_lnb_row> &inode_db_addr_list)
{
  uint t_rows = g_my_dev->lba_size_bytes / sizeof (data_lnb_row);
  std::vector<data_lnb_row> db_link_arr (t_rows);
  int ret = zns_udevice_read (g_my_dev, st_dblock_addr, db_link_arr.data (),
                              g_my_dev->lba_size_bytes);

  for (uint i = 0; i < t_rows - 1; i++)
    {
      if (db_link_arr[i].address == (uint)-1)
        {
          break;
        }
      inode_db_addr_list.push_back (db_link_arr[i]);
    }

  // check if there are more links
  if (db_link_arr[t_rows - 1].address != (uint)-1)
    {
      get_all_inode_data_links (db_link_arr[t_rows - 1].address,
                                inode_db_addr_list);
    }
}

// insert the data block addresses into the data block link address
int
insert_db_addrs_in_dlb (uint64_t dlb_address,
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

/*
 * cur_dlb - The data link block where to fill in the address details of the
 * newly filled blocks
 *
 * size - size of the buffer to write
 *
 * This function gets free blocks in the zns device the writes the buffer to
 * these blocks After writing to free blocks, it inserts the addresses into the
 * files's data link block
 *
 */
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

  // insert the written addresses into the data link block
  insert_db_addr_in_dlb (cur_dlb, free_block_list, size);
  return ret;
}

/*
 * will work for append files and write new files
 *
 * Structure of every file in zns device
 *
 * Inode -> Data Link Block ----> data block
 *                          ----> data block
 *                          ----> data block
 *                          ----> data block
 *                          -----> data link block -----> data block
 *
 * Every inode points to a data link block, every row in data link block points
 * to data blocks except the last row. The last row entry is reserved for a
 * data link block address if the file size increases
 */
int
write_data_from_address (uint64_t st_address, void *buf, size_t size)
{
  int ret = -ENOSYS;
  uint t_rows = g_my_dev->lba_size_bytes / sizeof (struct data_lnb_row);
  uint uf_bln = t_rows - 1;
  std::vector<data_lnb_row> data_lnb_arr (t_rows);
  std::vector<uint64_t> free_block_list;

  // get the first row with a partially filled block or empty data link
  ret = zns_udevice_read (g_my_dev, st_address, data_lnb_arr.data (),
                          g_my_dev->lba_size_bytes);

  for (uint i = 0; i < t_rows; i++)
    {
      // when a data block is partially filled
      if (data_lnb_arr[i].size != 0
          && data_lnb_arr[i].size < g_my_dev->lba_size_bytes)
        {
          uf_bln = i;
          break;
        }

      // when there is no address
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

  // when uf_bln has no address and is not the last row which is a link row
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
    struct fd_info fd_i = { filename, rfd, inode, 0, mode };

    // insert
    fd_table.insert (std::make_pair (rfd, fd_i));
  }
  ret = 0;
  return ret;
}

int
ar23_close (int fd)
{
  {
    std::lock_guard<std::mutex> lock (fd_mut);

    // update the file_write_table
    char *file_name = fd_table[fd].file_name;
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

  // getting the write mutex
  char *file_name = fd_table[fd].file_name;
  struct ar23_inode *inode_buf
      = (struct ar23_inode *)malloc (sizeof (struct ar23_inode));
  struct fd_info inode_info = fd_table[fd];
  uint64_t inode_address
      = get_inode_block_aligned_address (inode_info.inode_id);
  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_address, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf)
        + get_inode_byte_offset_in_block (inode_info.inode_id);
  memcpy (inode_buf, inode_offset, sizeof (struct ar23_inode));

  uint64_t data_block_st_addr = inode_buf->start_address;
  write_data_from_address (data_block_st_addr, (void *)buf, size);

  return ret;
}

// implemented without lseek  // perform errors checks with inode file size?
int
ar23_read (int fd, const void *buf, size_t size)
{
  int ret = -ENOSYS;
  uint64_t inode_id, inode_address, data_block_st_addr;
  struct ar23_inode *inode_buf;

  struct fd_info inode_info = fd_table[fd];
  inode_id = inode_info.inode_id;

  inode_address = get_inode_block_aligned_address (inode_id);

  // getting the starting block for the file reading inode metadata

  inode_buf = (struct ar23_inode *)malloc (sizeof (struct ar23_inode));
  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_address, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inode_id);
  memcpy (inode_buf, inode_offset, sizeof (struct ar23_inode));

  data_block_st_addr = inode_buf->start_address;

  ret = read_data_from_address (data_block_st_addr, (void *)buf, size);
  return ret;
}

int
init_root_inode (uint64_t iroot_saddr)
{

  int ret = ENOSYS;
  Inode iroot;
  iroot.start_addr = iroot_saddr;
  iroot.file_size = sizeof (Inode);
  iroot.i_type = 0;                            // directory
  std::time_t curr_time = std::time (nullptr); // Get current time
  iroot.i_ctime = curr_time;                   // Get current time
  iroot.i_mtime = iroot.i_ctime;

  // write root inode
  ret = zns_udevice_write (g_my_dev, iroot_saddr, &iroot, sizeof (Inode));
}

int
init_root_inode (uint64_t iroot_saddr)
{

  int ret = ENOSYS;
  Inode iroot;
  iroot.start_addr = iroot_saddr;
  iroot.file_size = sizeof (Inode);
  iroot.i_type = 0;                            // directory
  std::time_t curr_time = std::time (nullptr); // Get current time
  iroot.i_ctime = curr_time;                   // Get current time
  iroot.i_mtime = iroot.i_ctime;

  // write root inode
  ret = zns_udevice_write (g_my_dev, iroot_saddr, &iroot, sizeof (Inode));

  return ret;
}

// Path traversal function
std::vector<std::string>
path_to_vec (std::string path)
{ // returns a vec with path contents

  // path should be a full path
  std::vector<std::string> path_contents; // vector to store dir names

  size_t last_slash = path.find_last_of ("/\\"); // index of last slash
  std::string dir_path = path.substr (0, last_slash);
  std::string file_name = path.substr (last_slash + 1); // file name
  // std::cout << dir_path<< std::endl;
  // std::cout << file_name << std::endl;

  // Extracting directory names
  int start_p = 0;
  int end_p = path.find_first_of ("/\\");
  while (end_p != start_p)
    {
      std::string dir_name = path.substr (start_p, end_p);
      path_contents.push_back (dir_name);
      start_p = end_p + 1;
      end_p = path.find_first_of ("/\\");
    }
  return path_contents;
}

// Inode
// Get_file_inode (std::string path)
// { // Returns inode of file/dir

//   int ret = ENOSYS;
//   // path should be a full path
//   std::vector<std::string> path_contents
//       = path_to_vec (path); // vector to store dir names

InodeResult
Get_file_inode (std::string path)
{ // Returns inode of file/dir

  int ret = ENOSYS;
  // path should be a full path
  std::vector<std::string> path_contents
      = path_to_vec (path); // vector to store dir names

  int next_dir_inum;
  uint64_t next_inode_addr;
  Inode t_Inode;
  for (int i = 0; i < path_contents.size (); i++)
    {

      /* Inode Reading */
      char ibuf[sizeof (Inode)]; // buffer to read inode into
      // Get root dir start addr
      uint64_t inode_head = iroot.start_addr;
      uint32_t rdir_size = iroot.file_size;
      ret = read_data_from_address (inode_head, &ibuf,
                                    sizeof (Inode)); // get dir data

      // convert buffer into inode struct
      std::memcpy (&t_Inode, ibuf, sizeof (Inode));
      uint64_t t_dir_saddr = t_Inode.start_addr;
      uint16_t t_dir_size = t_Inode.file_size;

      // Quit if file or last dir
      if (i == path_contents.size ())
        {
          InodeResult ires;
          ires.inum = next_dir_inum;
          ires.inode = t_Inode;
          return ires;
        }

      /* Dir reading */
      std::vector<Dir_entry> dir_entries;
      ret = read_data_from_address (t_dir_saddr, dir_entries.data (),
                                    t_dir_size);

      // Find inode num of next dir
      for (int j = 0; j < dir_entries.size (); j++)
        {
          if (dir_entries[j].entry_name == path_contents[i + 1])
            {
              next_dir_inum = dir_entries[j].inum;
              break;
            }
        }

      // get next dir inode address & size
      next_inode_addr = get_inode_address (next_dir_inum);
      inode_head = next_inode_addr; // updation
    }
  InodeResult ires;
  ires.inum = next_dir_inum;
  ires.inode = t_Inode;

  return ires; // wont be used
}

/*
    update_path_sizes()

    Updates a inodes of all dirs in the path when a file/dir size changes

    delta: change in file_size

    sign: set to -1 if the file size is to be reduced

*/

int
update_path_isizes (std::string path, uint16_t delta, int sign)
{ // updating dir inodes of the file/dir size in the path
  // root > dir1 > dir2 > dir3 > file1(delta)
  int ret = ENOSYS;
  std::vector<std::string> path_contents = path_to_vec (path);
  std::string incr_path = "/";

  for (int i = 0; i < path_contents.size () - 1; i++)
    { // loop until the pdir of the file modified

      incr_path += path_contents[i];
      InodeResult ires = Get_file_inode (incr_path);
      Inode t_inode = ires.inode;
      update_inode_filesize (t_inode, delta, sign);
      // write inode back to
      ret = write_inode (ires.inum, t_inode);
    }

  return ret;
}

int
update_inode_filesize (Inode inode, uint16_t delta, int sign)
{

  inode.file_size
      = (sign < 0) ? inode.file_size - delta : inode.file_size + delta;
}

int
create_file (std::string path, uint16_t if_dir)
{
  int ret = ENOSYS;

  // Get file name from path
  std::vector<std::string> path_contents
      = path_to_vec (path);                      // vector to store dir names
  std::string file_name = path_contents.back (); // file name
  std::string pdir_name = path_contents[path_contents.size ()
                                        - 2]; // Parent Dir of file tb created
  size_t last_slash = path.find_last_of ("/\\"); // index of last slash
  std::string dir_path
      = path.substr (0, last_slash); // path of parent directory

  // Allocate inode block
  int i_num = -1;
  i_num = alloc_inode ();

  // Create Inode block
  Inode new_inode;
  uint64_t i_saddr = get_inode_address (i_num); ////

  // get start address of file
  uint64_t start_addr_file = alloc_dblock (); //// ??? check
  new_inode = init_inode (file_name, start_addr_file, 1,
                          if_dir); // 1 lba size bytes for data link block

  if (i_num == 1)
    {
      printf ("Inode area full\n");
      return -1;
    }

  // Write Inode to Inode region
  ret = write_inode (i_num, new_inode);

  // Update Inode bitmap
  update_inode_bitmap (i_num, true);

  // Update Dir entry
  InodeResult ires = Get_file_inode (dir_path);
  Inode pdir_inode = ires.inode;
  uint64_t pdir_saddr = pdir_inode.start_addr;
  uint16_t pdir_size = pdir_inode.file_size;

  /* Dir reading */
  std::vector<Dir_entry> dir_data_rows;
  ret = read_data_from_address (pdir_saddr, dir_data_rows.data (), pdir_size);

  Dir_entry dir_entry; // fill dir entry struct for new file
  dir_entry.inum = i_num;
  strncpy (dir_entry.entry_name, file_name.c_str (),
           sizeof (dir_entry.entry_name) - 1);
  dir_entry.entry_name[sizeof (dir_entry.entry_name) - 1]
      = '\0'; // have to test this conversion
  dir_entry.entry_type = 1;

  // Add new dir_entry to Dir_data and write back updated dir data vector
  dir_data_rows.push_back (dir_entry);
  std::vector<data_lnb_row> inode_db_addr_list;
  get_all_inode_data_links (pdir_saddr,
                            inode_db_addr_list); // all blks involed with dir

  // Update data bitmap
  update_db_bitmap (inode_db_addr_list, true);

  // Write updated dir data
  ret = write_to_free_data_blocks (&dir_data_rows, sizeof (dir_data_rows),
                                   start_addr_file); //// ??? to check

  return ret;
}

int
delete_file (std::string path)
{ // for now just dealing with files

  int ret = ENOSYS;
  // Get file inode num
  InodeResult ires = Get_file_inode (path);
  uint32_t inum = ires.inum;
  Inode inode = ires.inode;

  // Parent directory data updation
  std::vector<std::string> path_contents         // Get file name from path
      = path_to_vec (path);                      // vector to store dir names
  std::string file_name = path_contents.back (); // file name
  std::string pdir_name = path_contents[path_contents.size ()
                                        - 2]; // Parent Dir of file tb created
  size_t last_slash = path.find_last_of ("/\\"); // index of last slash
  std::string dir_path
      = path.substr (0, last_slash); // path of parent directory

  // Update Dir entry
  InodeResult pires = Get_file_inode (dir_path);
  Inode pdir_inode = pires.inode;
  uint64_t pdir_saddr = pdir_inode.start_addr;
  uint16_t pdir_size = pdir_inode.file_size;

  /* Dir reading */
  std::vector<Dir_entry> dir_data_rows;
  ret = read_data_from_address (pdir_saddr, dir_data_rows.data (), pdir_size);

  // Inode removal
  update_inode_bitmap (inum, false);

  // Data removal
  std::vector<data_lnb_row> inode_db_addr_list;
  get_all_inode_data_links (inode.start_addr, inode_db_addr_list);
  update_db_bitmap (inode_db_addr_list, false); // update data bitmap

  // parent directory updation
}

int
delete_dir (std::string path)
{
  int ret = ENOSYS;
  // Get file inode num
  InodeResult ires = Get_file_inode (path);
  uint32_t inum = ires.inum;
  Inode inode = ires.inode;

  //////// todo
}

bool
if_file_exists (std::string path)
{

  try
    {
      Get_file_inode (path);
    }
  catch (const std::runtime_error &e)
    {
      return false;
    }
  return true;
}

int
update_inode_bitmap (uint16_t inum, bool mark_valid)
{

  int ret = ENOSYS;
  uint64_t total_inodes = fs_my_dev->total_inodes;
  std::vector<bool> i_bitmap (total_inodes);
  ret = zns_udevice_read (g_my_dev, 0, &i_bitmap,
                          sizeof (i_bitmap)); // Read ibitmap
  i_bitmap[inum] = mark_valid;                // mark inum in ibitmap
  ret = zns_udevice_write (g_my_dev, 0, &i_bitmap, sizeof (i_bitmap));

  return ret;
}

int
update_db_bitmap (std::vector<data_lnb_row> inode_db_addr_list,
                  bool mark_valid)
{

  int ret = ENOSYS;
  int num_dblks = 10; // g_my_dev->num_dblks  to be changed
  uint64_t db_bitmap_saddr;
  std::vector<bool> db_bitmap (num_dblks);

  /* Release once read & write data bitmap funcs is converted to vector
  int read_data_bitmap(db_bitmap);

  for (int i = 0; i < inode_db_addr_list.size(); i++) {
    int db_num = (inode_db_addr_list[i].address -
  db_bitmap_saddr)/g_my_dev->lba_size_bytes; db_bitmap[db_num] = mark_valid;
  }

  write_data_bitmap(db_bitmap);
  */
}

/*
  read_inode()

  Reads the inode adjusting for block addressing

*/
Inode
read_inode (uint32_t inum)
{

  int ret = ENOSYS;
  uint64_t inode_blk_addr = get_inode_block_aligned_address (inum);

  // getting the starting block for the file reading inode metadata
  struct Inode *inode_buf;
  inode_buf = (struct Inode *)malloc (sizeof (struct Inode));
  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_blk_addr, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inum);
  memcpy (inode_buf, inode_offset, sizeof (struct Inode));

  return inode_buf;
}

/*
  write_inode()

  Writes the inode adjusting for block addressing

*/
int
write_inode (uint32_t inum, Inode inode_w)
{

  int ret = ENOSYS;
  uint64_t inode_blk_addr = get_inode_block_aligned_address (inum);

  // getting the starting block for the file reading inode metadata
  struct Inode *inode_buf;
  inode_buf = (struct Inode *)malloc (sizeof (struct Inode));
  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_blk_addr, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inum);

  memcpy (inode_offset, &inode_w,
          sizeof (struct Inode)); // copy new inode into read blk

  ret = zns_udevice_write (
      g_my_dev, inode_blk_addr, lba_buf,
      g_my_dev->lba_size_bytes); // write the updated lba blk back

  return ret;
}

// Initializes Inode struct
Inode
init_inode (std::string file_name, uint64_t start_addr, int file_size,
            uint16_t if_dir)
{

  Inode new_inode;
  strncpy (new_inode.file_name, file_name.c_str (),
           sizeof (new_inode.file_name) - 1);
  new_inode.file_name[sizeof (new_inode.file_name) - 1] = '\0';
  new_inode.start_addr = start_addr;
  new_inode.file_size = file_size;
  new_inode.i_type = if_dir;
  return new_inode;
}

// Allocate DB return next free db
int
alloc_dblock ()
{

  int ret = ENOSYS;

  // get data bitmap
  std::vector<bool> db_bitmap (fs_my_dev->total_data_blocks);
  ret = zns_udevice_read (g_my_dev, 0, &db_bitmap,
                          fs_my_dev->total_data_blocks);

  // Read DBitmap
  ret = zns_udevice_read (g_my_dev, 0, &db_bitmap,
                          fs_my_dev->total_data_blocks);

  // Find next free db & mark as used
  int new_db_num = -1;
  for (int i = 0; i < sizeof (db_bitmap) / sizeof (db_bitmap[0]); i++)
    {
      if (db_bitmap[i] == false)
        {
          db_bitmap[i] = true;
          new_db_num = i;
          break;
        }
    }

  if (new_db_num == -1)
    {
      std::cout << "Inode Bitmap full" << std::endl;
    }

  return new_db_num;
}

// Allocate iNode returns i_id
int
alloc_inode ()
{

  int ret = ENOSYS;
  // get inode_bitmap
  uint64_t total_inodes = fs_my_dev->total_inodes;
  std::vector<bool> i_bitmap (total_inodes);

  // Read iBitmap
  ret = zns_udevice_read (g_my_dev, 0, &i_bitmap, sizeof (i_bitmap));

  // Find next free inode id & mark as used
  int new_inode_id = -1;
  for (int i = 0; i < sizeof (i_bitmap) / sizeof (i_bitmap[0]); i++)
    {
      if (i_bitmap[i] == false)
        {
          i_bitmap[i] = true;
          new_inode_id = i;
          break;
        }
    }

  if (new_inode_id == -1)
    {
      std::cout << "Inode Bitmap full" << std::endl;
    }

  return new_inode_id;
}
