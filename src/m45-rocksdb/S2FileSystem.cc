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
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <vector>

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
uint32_t g_fd_count; // always points to the next available fd
std::mutex fd_mut;
std::mutex bitmap_mut; // mutex for when making changes to the bitmap

struct user_zns_device *g_my_dev;
struct fs_zns_device *fs_my_dev;
struct s2fs_inode *iroot;

// this may not be block allocated
uint64_t
get_inode_address (uint64_t inum)
{
  return fs_my_dev->inode_table_address + (inum * sizeof (s2fs_inode));
}

uint64_t
get_inode_block_aligned_address (uint64_t inum)
{
  uint64_t i_addr = get_inode_address (inum);
  uint64_t rem = i_addr % g_my_dev->lba_size_bytes;
  return i_addr - rem;
}

uint64_t
get_inode_byte_offset_in_block (uint64_t inum)
{

  uint64_t inode_addr = get_inode_address (inum);
  uint64_t inode_block_al_addr = get_inode_block_aligned_address (inum);
  return inode_addr - inode_block_al_addr;
}

// is logical block aligned always
uint64_t
get_dnum_address (uint64_t dnum)
{
  return fs_my_dev->data_address + (dnum * g_my_dev->lba_size_bytes);
}

int
write_data_block (void *data_block, uint64_t address)
{
  int ret = zns_udevice_write (g_my_dev, address, data_block,
                               g_my_dev->lba_size_bytes);
  return ret;
}

int
read_data_bitmap (void *data_bitmap)
{
  int ret = zns_udevice_read (g_my_dev, fs_my_dev->data_bitmap_address,
                              data_bitmap, fs_my_dev->data_bitmap_size);
  return ret;
}

int
write_data_bitmap (void *data_bitmap)
{
  int ret = zns_udevice_write (g_my_dev, fs_my_dev->data_bitmap_address,
                               data_bitmap, fs_my_dev->data_bitmap_size);
  return ret;
}

int
update_data_bitmap (std::vector<uint64_t> dnums, bool val)
{
  int ret = -ENOSYS;

  void *data_bm_buf = malloc (fs_my_dev->data_bitmap_size);
  {
    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = read_data_bitmap (data_bm_buf);

    std::vector<bool> *vec_data_bitmap
        = static_cast<std::vector<bool> *> (data_bm_buf);

    for (uint i = 0; i < dnums.size (); i++)
      {
        (*vec_data_bitmap)[dnums[i]] = val;
      }

    ret = write_data_bitmap (data_bm_buf);
    free (data_bm_buf);
  }
  return ret;
}

int
read_inode_bitmap (void *inode_bitmap)
{
  int ret = zns_udevice_read (g_my_dev, fs_my_dev->inode_bitmap_address,
                              inode_bitmap, fs_my_dev->inode_bitmap_size);
  return ret;
}

int
write_inode_bitmap (void *inode_bitmap)
{

  int ret = zns_udevice_write (g_my_dev, fs_my_dev->inode_bitmap_address,
                               inode_bitmap, fs_my_dev->inode_bitmap_size);

  return ret;
}

int
update_inode_bitmap (std::vector<uint64_t> inums, bool val)
{
  int ret = -ENOSYS;
  void *inode_bm_buf = malloc (fs_my_dev->inode_bitmap_size);
  {

    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = read_inode_bitmap (inode_bm_buf);

    std::vector<bool> *vec_inode_bitmap
        = static_cast<std::vector<bool> *> (inode_bm_buf);

    for (uint i = 0; i < inums.size (); i++)
      {
        (*vec_inode_bitmap)[inums[i]] = val;
      }

    ret = write_inode_bitmap (inode_bm_buf);

    free (inode_bm_buf);
  }
  return ret;
}

int
read_inode (uint64_t inum, struct s2fs_inode *inode)
{

  int ret = -ENOSYS;
  uint64_t inode_blk_addr = get_inode_block_aligned_address (inum);

  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_blk_addr, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inum);
  memcpy (inode, inode_offset, sizeof (struct s2fs_inode));

  free (lba_buf);

  return ret;
}

int
write_inode (uint64_t inum, struct s2fs_inode *inode)
{

  int ret = ENOSYS;
  uint64_t inode_blk_addr = get_inode_block_aligned_address (inum);

  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_blk_addr, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inum);

  memcpy (inode_offset, inode,
          sizeof (struct s2fs_inode)); // copy new inode into read blk

  ret = zns_udevice_write (
      g_my_dev, inode_blk_addr, lba_buf,
      g_my_dev->lba_size_bytes); // write the updated lba blk back

  free (lba_buf);
  return ret;
}

int
alloc_inode (uint64_t &inum)
{

  int ret = -ENOSYS;
  // get inode_bitmap

  void *inode_bm_buf = malloc (fs_my_dev->inode_bitmap_size);
  {

    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = read_inode_bitmap (inode_bm_buf);
    std::vector<bool> *vec_inode_bm
        = static_cast<std::vector<bool> *> (inode_bm_buf);

    int new_inode_id = -1;
    for (uint i = 0; i < (*vec_inode_bm).size (); i++)
      {
        if ((*vec_inode_bm)[i] == false)
          {
            (*vec_inode_bm)[i] = true;
            new_inode_id = i;
            break;
          }
      }

    ret = write_inode_bitmap (inode_bm_buf);

    if (new_inode_id == -1)
      {
        std::cout << "Inode Bitmap full" << std::endl;
        return ret;
      }

    inum = new_inode_id;
    free (inode_bm_buf);
  }
  return ret;
}

int
get_free_data_blocks (uint64_t size, std::vector<uint64_t> &free_block_list)
{
  int ret = -ENOSYS;
  {
    std::lock_guard<std::mutex> lock (bitmap_mut);

    // read datablock bitmap
    void *data_bitmap = malloc (fs_my_dev->data_bitmap_size);
    std::vector<uint64_t> free_dnum_list;

    uint32_t total_blocks_to_alloc
        = size / g_my_dev->lba_size_bytes
          + (size % g_my_dev->lba_size_bytes > 0 ? 1 : 0);

    read_data_bitmap (data_bitmap);

    std::vector<bool> *vec_data_bitmap
        = static_cast<std::vector<bool> *> (data_bitmap);
    for (uint i = 0; i < vec_data_bitmap->size (); i++)
      {
        if ((*vec_data_bitmap)[i] == false)
          {
            free_dnum_list.push_back (i);
          }
      }

    // when not enough data blocks
    if (total_blocks_to_alloc != free_dnum_list.size ())
      {
        ret = -1;
      }
    else
      {
        for (uint i = 0; i < free_dnum_list.size (); i++)
          {
            free_block_list.push_back (get_dnum_address (free_dnum_list[i]));
            (*vec_data_bitmap)[free_dnum_list[i]] = true;
          }

        write_data_bitmap (data_bitmap);
        ret = 0;
      }
  }
  return ret;
};

// initialize the root inode
int
init_iroot ()
{

  int ret = -ENOSYS;
  iroot = (struct s2fs_inode *)malloc (sizeof (struct s2fs_inode));

  std::vector<uint64_t> t_free_block_list;

  // get two free datablocks (one for dlb, one for root dir entries)
  get_free_data_blocks ((g_my_dev->lba_size_bytes) * 2, t_free_block_list);

  uint dir_rows = g_my_dev->lba_size_bytes / sizeof (struct Dir_entry);
  uint dlb_rows = g_my_dev->lba_size_bytes / sizeof (struct data_lnb_row);

  std::vector<data_lnb_row> dlb_block (dlb_rows, { 0, 0 });
  std::vector<Dir_entry> root_dir_block (dir_rows, { 0, 0, "", "" });
  dlb_block[0].address = t_free_block_list[1];
  dlb_block[0].size = g_my_dev->lba_size_bytes;

  write_data_block (dlb_block.data (), t_free_block_list[0]);
  write_data_block (root_dir_block.data (), t_free_block_list[1]);

  iroot->start_addr = t_free_block_list[0];
  iroot->file_size = g_my_dev->lba_size_bytes;
  iroot->i_type = 0; // directory

  std::time_t curr_time = std::time (nullptr);
  iroot->i_ctime = curr_time;
  iroot->i_mtime = curr_time;

  // write root inode
  ret = write_inode (0, iroot);
  return ret;
}

// init the file system
int
s2fs_init (struct user_zns_device *my_dev)
{
  int ret = -ENOSYS;
  uint64_t tot_lba, pad, inode_bmap_byte_size, data_bmap_byte_size;
  // struct zns_dev_params *zns_dev;
  void *inode_bmap_buf, *data_bmap_buf;

  g_my_dev = my_dev;

  // read persistent storage information

  // init zns device by setting up bitmaps
  fs_my_dev = (struct fs_zns_device *)malloc (sizeof (struct fs_zns_device));

  // zns_dev = (struct zns_dev_params *)g_my_dev->_private;
  tot_lba = g_my_dev->capacity_bytes / g_my_dev->lba_size_bytes;

  uint64_t _t_x = tot_lba / 16; // (magic number: divinding inode to data
                                // blocks in the ratio 1:15)
  fs_my_dev->total_inodes = _t_x;
  fs_my_dev->total_data_blocks = _t_x * 15;

  // write inode bit map data
  uint64_t inode_bmap_bit_size = _t_x;
  uint64_t pad_bits = inode_bmap_bit_size % 8;
  inode_bmap_byte_size = (inode_bmap_bit_size + pad_bits) / 8;

  // align inode_bmap at lba size
  if (inode_bmap_byte_size % g_my_dev->lba_size_bytes != 0)
    {
      if (inode_bmap_byte_size < my_dev->lba_size_bytes)
        {
          inode_bmap_byte_size = my_dev->lba_size_bytes;
        }
      else
        {
          pad = g_my_dev->lba_size_bytes
                - (inode_bmap_byte_size % my_dev->lba_size_bytes);
          inode_bmap_byte_size += pad;
        }
    }

  inode_bmap_buf = malloc (inode_bmap_byte_size);
  memset (inode_bmap_buf, 0, inode_bmap_byte_size);

  fs_my_dev->inode_bitmap_address = 0x00;
  fs_my_dev->inode_bitmap_size = inode_bmap_byte_size;
  ret = zns_udevice_write (my_dev, fs_my_dev->inode_bitmap_address,
                           inode_bmap_buf, fs_my_dev->inode_bitmap_size);

  // write data bitmap
  fs_my_dev->data_bitmap_address
      = fs_my_dev->inode_bitmap_address + fs_my_dev->inode_bitmap_size;
  uint64_t data_bmap_bit_size = fs_my_dev->total_data_blocks;
  pad_bits = data_bmap_bit_size % 8;
  data_bmap_byte_size = (data_bmap_bit_size + pad_bits) / 8;

  if (data_bmap_byte_size % my_dev->lba_size_bytes != 0)
    {
      if (data_bmap_byte_size < my_dev->lba_size_bytes)
        {
          data_bmap_byte_size = my_dev->lba_size_bytes;
        }
      else
        {
          pad = g_my_dev->lba_size_bytes
                - (data_bmap_byte_size % my_dev->lba_size_bytes);
          data_bmap_byte_size += pad;
        }
    }

  data_bmap_buf = malloc (data_bmap_byte_size);
  memset (data_bmap_buf, 0, data_bmap_byte_size);
  fs_my_dev->data_bitmap_size = data_bmap_byte_size;
  ret = zns_udevice_write (my_dev, fs_my_dev->data_bitmap_address,
                           data_bmap_buf, fs_my_dev->data_bitmap_size);

  // set up inode table address and starting data block address
  fs_my_dev->inode_table_address
      = fs_my_dev->data_bitmap_address + fs_my_dev->data_bitmap_size;
  fs_my_dev->data_address
      = fs_my_dev->inode_table_address + (sizeof (struct s2fs_inode) * _t_x);

  // setup first inode and root directory
  init_iroot ();

  free (inode_bmap_buf);
  free (data_bmap_buf);

  return ret;
}

int
s2fs_deinit ()
{
  // push unpushed metadata onto the device for persistent storage
  free (fs_my_dev);
  free (iroot);
  return 0;
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
read_data_from_address (uint64_t st_addr, void *buf, size_t size)
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
  ret = zns_udevice_read (g_my_dev, st_addr, data_lnb_arr.data (),
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
  zns_udevice_read (g_my_dev, st_dblock_addr, db_link_arr.data (),
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

      std::vector<uint64_t> t_free_block_list;
      uint64_t free_dlb;
      ret = get_free_data_blocks (g_my_dev->lba_size_bytes, t_free_block_list);

      // could not get free dlb block to write
      if (ret == -1)
        {
          return ret;
        }

      free_dlb = t_free_block_list[-1];
      // insert link block where remaining free blocks will be inserted
      data_lnb_arr[t_rows - 1].address = t_free_block_list[0];

      // write updated link data block
      ret = zns_udevice_write (g_my_dev, dlb_address, data_lnb_arr.data (),
                               g_my_dev->lba_size_bytes);
      ret = insert_db_addrs_in_dlb (free_dlb, free_block_list, t_size);
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
  ret = insert_db_addrs_in_dlb (cur_dlb, free_block_list, size);
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
 *
 * The function below tries to the get a dlb block with free indexes (dlb block
 * where links to data blocks can be inserted)
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
      uint32_t rem_free_bytes
          = g_my_dev->lba_size_bytes - data_lnb_arr[uf_bln].size;

      // write the rem_free_bytes to the block
      void *fl_buf = malloc (g_my_dev->lba_size_bytes);
      ret = zns_udevice_read (g_my_dev, data_lnb_arr[uf_bln].address, fl_buf,
                              g_my_dev->lba_size_bytes);
      uint8_t *t_fl_buf = ((uint8_t *)fl_buf) + data_lnb_arr[uf_bln].size;
      memcpy (t_fl_buf, buf, rem_free_bytes);
      ret = zns_udevice_write (g_my_dev, data_lnb_arr[uf_bln].address, fl_buf,
                               g_my_dev->lba_size_bytes);
      t_fl_buf = ((uint8_t *)buf) + rem_free_bytes;

      data_lnb_arr[uf_bln].size = g_my_dev->lba_size_bytes;
      write_to_free_data_blocks (t_fl_buf, size - rem_free_bytes, st_address);
    }

  // when uf_bln has no address and is not the last row which is a link row
  else if (data_lnb_arr[uf_bln].size == 0 && uf_bln != t_rows - 1)
    {
      ret = write_to_free_data_blocks (buf, size, st_address);
    }

  // when current dlb is full
  else
    {
      // dlb at last index has data or not
      if (data_lnb_arr[uf_bln].address == (uint)-1)
        {
          std::vector<uint64_t> t_free_block_list;
          ret = get_free_data_blocks (g_my_dev->lba_size_bytes,
                                      t_free_block_list);

          // couldn't get a free data block
          if (ret == -1)
            {
              return ret;
            }

          data_lnb_arr[uf_bln].address = t_free_block_list[0];
          ret = write_data_from_address (data_lnb_arr[uf_bln].address, buf,
                                         size);
        }

      else
        {
          ret = write_data_from_address (data_lnb_arr[uf_bln].address, buf,
                                         size);
        }
    }

  // write the updated dlb block
  ret = zns_udevice_write (g_my_dev, st_address, data_lnb_arr.data (),
                           g_my_dev->lba_size_bytes);
  return ret;
}

int
s2fs_open (char *filename, int oflag, mode_t mode)
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
s2fs_close (int fd)
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
s2fs_write (int fd, const void *buf, size_t size)
{
  // every write has to be from +8 bytes as there is metadata
  int ret = -ENOSYS;

  char *file_name = fd_table[fd].file_name;
  struct s2fs_inode *inode_buf
      = (struct s2fs_inode *)malloc (sizeof (struct s2fs_inode));

  struct fd_info inode_info = fd_table[fd];
  uint64_t inode_address
      = get_inode_block_aligned_address (inode_info.inode_id);
  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_address, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf)
        + get_inode_byte_offset_in_block (inode_info.inode_id);
  memcpy (inode_buf, inode_offset, sizeof (struct s2fs_inode));

  uint64_t data_block_st_addr = inode_buf->start_addr;
  write_data_from_address (data_block_st_addr, (void *)buf, size);

  return ret;
}

// implemented without lseek  // perform errors checks with inode file size?
int
s2fs_read (int fd, const void *buf, size_t size)
{
  int ret = -ENOSYS;
  uint64_t inode_id, inode_address, data_block_st_addr;
  struct s2fs_inode *inode_buf;

  struct fd_info inode_info = fd_table[fd];
  inode_id = inode_info.inode_id;

  inode_address = get_inode_block_aligned_address (inode_id);

  // getting the starting block for the file reading inode metadata

  inode_buf = (struct s2fs_inode *)malloc (sizeof (struct s2fs_inode));
  void *lba_buf = malloc (g_my_dev->lba_size_bytes);
  ret = zns_udevice_read (g_my_dev, inode_address, lba_buf,
                          g_my_dev->lba_size_bytes);

  uint8_t *inode_offset
      = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inode_id);
  memcpy (inode_buf, inode_offset, sizeof (struct s2fs_inode));

  data_block_st_addr = inode_buf->start_addr;

  ret = read_data_from_address (data_block_st_addr, (void *)buf, size);
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
  s2fs_inode t_Inode;
  for (int i = 0; i < path_contents.size (); i++)
    {

      /* Inode Reading */
      char ibuf[sizeof (s2fs_inode)]; // buffer to read inode into
      // Get root dir start addr
      uint64_t inode_head = iroot->start_addr;
      uint32_t rdir_size = iroot->file_size;
      ret = read_data_from_address (inode_head, &ibuf,
                                    sizeof (s2fs_inode)); // get dir data

      // convert buffer into inode struct
      std::memcpy (&t_Inode, ibuf, sizeof (s2fs_inode));
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
      s2fs_inode t_inode = ires.inode;
      update_inode_filesize (t_inode, delta, sign);
      // write inode back to
      ret = write_inode (ires.inum, &t_inode);
    }

  return ret;
}

int
update_inode_filesize (s2fs_inode inode, uint16_t delta, int sign)
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
  uint64_t i_num;
  ret = alloc_inode (i_num);

  // Create Inode block
  s2fs_inode new_inode;
  uint64_t i_saddr = get_inode_address (i_num); ////

  // get start address of file
  std::vector<uint64_t> t_free_block_list;
  uint64_t start_addr
      = get_free_data_blocks (g_my_dev->lba_size_bytes, t_free_block_list);
  new_inode = init_inode (file_name, start_addr, 1,
                          if_dir); // 1 lba size bytes for data link block
  if (i_num == 1)
    {
      printf ("Inode area full\n");
      return -1;
    }

  // Write Inode to Inode region
  ret = write_inode (i_num, &new_inode);

  // Update Inode bitmap
  std::vector<uint64_t> inums;
  inums.push_back (i_num);
  update_inode_bitmap (inums, true);

  // Update Dir entry
  InodeResult ires = Get_file_inode (dir_path);
  s2fs_inode pdir_inode = ires.inode;
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

  // call update_data_bitmap() -- here
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
  s2fs_inode inode = ires.inode;

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
  s2fs_inode pdir_inode = pires.inode;
  uint64_t pdir_saddr = pdir_inode.start_addr;
  uint16_t pdir_size = pdir_inode.file_size;

  /* Dir reading */
  std::vector<Dir_entry> dir_data_rows;
  ret = read_data_from_address (pdir_saddr, dir_data_rows.data (), pdir_size);

  // Inode removal
  std::vector<uint64_t> inums;
  inums.push_back (inum);
  update_inode_bitmap (inums, false);

  // Data removal
  std::vector<data_lnb_row> inode_db_addr_list;
  get_all_inode_data_links (inode.start_addr, inode_db_addr_list);

  // call update_data_bitmap() -- here
}

int
delete_dir (std::string path)
{
  int ret = ENOSYS;
  // Get file inode num
  InodeResult ires = Get_file_inode (path);
  uint32_t inum = ires.inum;
  s2fs_inode inode = ires.inode;

  //////// todo
}

// ? error catching??
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

// Initializes Inode struct
s2fs_inode
init_inode (std::string file_name, uint64_t start_addr, int file_size,
            uint16_t if_dir)
{

  s2fs_inode new_inode;
  strncpy (new_inode.file_name, file_name.c_str (),
           sizeof (new_inode.file_name) - 1);
  new_inode.file_name[sizeof (new_inode.file_name) - 1] = '\0';
  new_inode.start_addr = start_addr;
  new_inode.file_size = file_size;
  new_inode.i_type = if_dir;
  return new_inode;
}
