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

#include "rocksdb/env.h"
#include "rocksdb/file_system.h"
#include "rocksdb/io_status.h"
#include "zns_device.h"
#include <asm-generic/errno.h>
#include <cstdint>
#include <iostream>
#include <math.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <vector>

#include "S2FileSystem.h"
#include <stosys_debug.h>
#include <utils.h>

/* Things to implement
 *
 * GetAbsolutePath <
 * CreateDirIfMissing <
 * FileExists <
 * RenameFile <
 * NewLogger <
 * GetChildren <
 * GetFileSize
 * NewDirectory <
 * LockFile
 * NewRandomAccessFile <
 * NewSequentialFile <
 * NewWritableFile <
 * DeleteFile <
 */

namespace ROCKSDB_NAMESPACE
{

std::string
san_path (std::string path)
{

  std::string result;
  uint64_t var = 0;
  while ((var = path.find ("//", var)) != std::string::npos)
    {
      path.replace (var, 2, "/");
      var++;
    }

  if (path.length () > 1 && path.back () == '/')
    {
      path.pop_back ();
    }

  return path;
}

S2SequentialFile::S2SequentialFile (std::string path)
{
  this->fd = s2fs_open (path, 0, 0);
  this->offset = 0;
}
S2SequentialFile::~S2SequentialFile () { s2fs_close (this->fd); }

IOStatus
S2SequentialFile::Read (size_t n, const IOOptions &options, Slice *result,
                        char *scratch, IODebugContext *dbg)
{
  uint64_t bytes_read = 0;
  int ret = s2fs_read (this->fd, scratch, n, this->offset, bytes_read);
  *result = Slice (scratch, bytes_read);

  if (ret == -1){
    *result = Slice(scratch, 0);
    return IOStatus::OK();
  }

  this->offset += bytes_read;
  return IOStatus::OK ();
}

// check if you need to implement offset
IOStatus
S2SequentialFile::Skip (uint64_t n)
{
  this->offset += n;
  return IOStatus::OK ();
}

S2WritableFile::S2WritableFile (std::string path)
{
  this->fd = s2fs_open (path, 0, 0);
}

S2WritableFile::~S2WritableFile (){};

IOStatus
S2WritableFile::Append (const Slice &data, const IOOptions &options,
                        IODebugContext *dbg)
{
  int ret = s2fs_write (fd, (void *)data.data (), data.size (), (uint64_t)-1);
  if (ret == -1)
    return IOStatus::IOError ();
  return IOStatus::OK ();
}

IOStatus
S2WritableFile::Close (const IOOptions &options, IODebugContext *dbg)
{
  s2fs_close (this->fd);
  return IOStatus::OK ();
}

IOStatus
S2WritableFile::Flush (const IOOptions &options, IODebugContext *dbg)
{
  return IOStatus::OK ();
}

IOStatus
S2WritableFile::Sync (const IOOptions &options, IODebugContext *dbg)
{
  return IOStatus::OK ();
}

S2RandomAccessFile::S2RandomAccessFile (std::string path)
{
  this->fd = s2fs_open (path, 0, 0);
}

S2RandomAccessFile::~S2RandomAccessFile () { s2fs_close (this->fd); }

IOStatus
S2RandomAccessFile::Read (uint64_t offset, size_t n, const IOOptions &options,
                          Slice *result, char *scratch,
                          IODebugContext *dbg) const
{

  // int ret = s2fs_read (this->fd, scratch, n, offset);

  // if (ret == -1)
  //   return IOStatus::IOError (__FUNCTION__);
  return IOStatus::OK ();
}

S2Logger::S2Logger () {}
S2Logger::~S2Logger () {}
S2FSDirectory::S2FSDirectory () {}
IOStatus
S2FSDirectory::Fsync (const IOOptions &options, IODebugContext *dbg)
{
  return IOStatus::OK ();
}
S2FSDirectory::~S2FSDirectory () {}
} // namespace ROCKSDB_NAMESPACE

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
  ret = s2fs_init (this->_zns_dev);

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

S2FileSystem::~S2FileSystem ()
{
  deinit_ss_zns_device (this->_zns_dev);
  s2fs_deinit ();
}

IOStatus
S2FileSystem::IsDirectory (const std::string &, const IOOptions &options,
                           bool *is_dir, IODebugContext *)
{
  return IOStatus::IOError (__FUNCTION__);
}
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
  int ret = s2fs_create_file (san_path (fname), false);
  if (ret == -1)
    return IOStatus::NotFound();
  result->reset (new S2SequentialFile (san_path (fname)));
  return IOStatus::OK ();
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
 // int ret = s2fs_create_file (san_path (fname), false);
  // if (ret == -1)
  //   return IOStatus::IOError (__FUNCTION__);
  result->reset (new S2RandomAccessFile (san_path (fname)));
  return IOStatus::OK ();
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
  int ret = s2fs_create_file (san_path (fname), false);
  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);

  result->reset (new S2WritableFile (san_path (fname)));
  return IOStatus::OK ();
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
  std::string dir_path = san_path (name);
  int ret = s2fs_create_file (dir_path, true);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);

  result->reset (new S2FSDirectory ());

  return IOStatus::OK ();
}

const char *
S2FileSystem::Name () const
{
  return "S2FileSytem";
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
  std::string path = san_path (dirname);
  bool file_exists = s2fs_file_exists (path);

  if (file_exists)
    return IOStatus::OK ();

  int ret = s2fs_create_file (path, true);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  return IOStatus::OK ();
}

IOStatus
S2FileSystem::GetFileSize (const std::string &fname, const IOOptions &options,
                           uint64_t *file_size,
                           __attribute__ ((unused)) IODebugContext *dbg)
{
  uint64_t fs;
 int ret = s2fs_get_file_size (san_path (fname), fs);
  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  *file_size = fs;
  return IOStatus::OK ();
}

IOStatus
S2FileSystem::DeleteDir (const std::string &dirname, const IOOptions &options,
                         __attribute__ ((unused)) IODebugContext *dbg)
{
 int ret = s2fs_delete (san_path (dirname), true);
  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  return IOStatus::OK ();
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
  *output_path = san_path (db_path);
  return IOStatus::OK ();
}

IOStatus
S2FileSystem::DeleteFile (const std::string &fname, const IOOptions &options,
                          __attribute__ ((unused)) IODebugContext *dbg)
{
 int ret = s2fs_delete (san_path (fname), false);
  //printf("Delete file: %s \n", fname.c_str());
  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  return IOStatus::OK ();
}

IOStatus
S2FileSystem::NewLogger (const std::string &fname, const IOOptions &io_opts,
                         std::shared_ptr<Logger> *result,
                         __attribute__ ((unused)) IODebugContext *dbg)
{
  // std::string log_path = this->_uri + fname;
  // s2fs_create_file (log_path, false);
  // std::shared_ptr<Logger> s2_ptr = std::make_shared<S2Logger> ();
  // result = &s2_ptr;
  return IOStatus::OK ();
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
  return IOStatus::OK ();
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
  return IOStatus::OK ();
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
  std::string src_path = san_path (src);
  std::string target_path = san_path (target);

 int ret = s2fs_move_file (src_path, target_path);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  else
    return IOStatus::OK ();
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
  std::string dir_path = san_path (dir); 
  int ret = s2fs_get_dir_children (dir_path, result);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  return IOStatus::OK ();
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
  std::string path = san_path (fname);
  bool file_exists = s2fs_file_exists (path);

  if (file_exists)
    return IOStatus::OK ();
  else
    return IOStatus::NotFound ();
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
} // namespace ROCKSDB_NAMESPACE

std::unordered_map<uint32_t, fd_info> fd_table;
uint32_t g_fd_count; // always points to the next available fd
std::mutex fd_mut;
std::mutex bitmap_mut; // mutex for when making changes to the bitmap
std::mutex inode_mut;  // mutex for reading and writing to inode
std::mutex dir_mut;    // mutex for making changes to a directory

struct user_zns_device *g_my_dev;
struct fs_zns_device *fs_my_dev;
struct s2fs_inode *iroot;

uint64_t
ceil_dirb_rows (long long int size)
{
  double quo = double (size) / fs_my_dev->dirb_rows;
  quo = std::ceil (quo);
  uint64_t ceil_addr = (uint64_t)quo * fs_my_dev->dirb_rows;
  return ceil_addr;
}

uint64_t
ceil_lba (long long int addr)
{
  double quo = double (addr) / g_my_dev->lba_size_bytes;
  quo = std::ceil (quo);
  uint64_t ceil_addr = (uint64_t)quo * g_my_dev->lba_size_bytes;
  return ceil_addr;
}

uint64_t
floor_lba (long long int addr)
{
  double quo = double (addr) / g_my_dev->lba_size_bytes;
  quo = std::floor (quo);
  uint64_t ceil_addr = (uint64_t)quo * g_my_dev->lba_size_bytes;
  return ceil_addr;
}

uint32_t
ceil_byte (int bits)
{
  double quo = double (bits) / 8;
  quo = std::ceil (quo);
  uint64_t ceil_addr = (uint64_t)quo * 8;
  return ceil_addr;
}

uint32_t
floor_byte (int bits)
{
  double quo = double (bits) / 8;
  quo = std::floor (quo);
  uint64_t ceil_addr = (uint64_t)quo * 8;
  return ceil_addr;
}

// this may not be block aligned
uint64_t
get_inode_address (uint64_t inum)
{
  return fs_my_dev->inode_table_address + (inum * sizeof (s2fs_inode));
}

uint64_t
get_inode_block_aligned_address (uint64_t inum)
{
  uint64_t i_addr = get_inode_address (inum);
 return floor_lba (i_addr);
}

uint64_t
get_inode_byte_offset_in_block (uint64_t inum)
{

  uint64_t inode_addr = get_inode_address (inum);
  uint64_t inode_block_al_addr = get_inode_block_aligned_address (inum);
  return inode_addr - inode_block_al_addr;
}

int
read_data_block (void *data_block, uint64_t address)
{
  int ret = zns_udevice_read (g_my_dev, address, data_block,
                              g_my_dev->lba_size_bytes);
  return ret;
}

int
write_data_block (void *data_block, uint64_t address)
{
  int ret = zns_udevice_write (g_my_dev, address, data_block,
                               g_my_dev->lba_size_bytes);
  return ret;
}

// write to a partially filled data block
int
write_pf_data_block (void *buf, uint64_t address, uint32_t lba_offset,
                     uint64_t buf_size)
{
  void *lba_block = malloc (g_my_dev->lba_size_bytes);
  int ret = read_data_block (lba_block, address);

  uint8_t *cp_offset = ((uint8_t *) lba_block) + lba_offset;
  memcpy (cp_offset, buf, buf_size);

  ret = write_data_block (lba_block, address);
  free (lba_block);
  return ret;
}

// init a dir data block
void
init_dir_data (std::vector<dir_entry> &dir, uint64_t size)
{
  struct dir_entry def;
  def.inum = (uint64_t)-1;
  def.entry_type = 0;
  std::strcpy (def.entry_name, "");
  dir.resize (size, def);
}

// initialize a data block as an indirect block
int
init_dlb_data_block (uint64_t address)
{
  std::vector<data_lnb_row> init_dlb (fs_my_dev->dlb_rows,
                                      { (uint64_t)-1, 0 });
  int ret = write_data_block (init_dlb.data (), address);
  return ret;
}

int
read_inode (uint64_t inum, struct s2fs_inode *inode)
{

  int ret = -ENOSYS;
  {
    std::lock_guard<std::mutex> lock (inode_mut);
    uint64_t inode_blk_addr = get_inode_block_aligned_address (inum);

    void *lba_buf = malloc (g_my_dev->lba_size_bytes);
    ret = read_data_block (lba_buf, inode_blk_addr);

    uint8_t *inode_offset
        = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inum);
    memcpy (inode, inode_offset, sizeof (struct s2fs_inode));

    free (lba_buf);
  }

  return ret;
}

int
write_inode (uint64_t inum, struct s2fs_inode *inode)
{

  int ret = ENOSYS;
  {
    std::lock_guard<std::mutex> lock (inode_mut);
    uint64_t inode_blk_addr = get_inode_block_aligned_address (inum);

    void *lba_buf = malloc (g_my_dev->lba_size_bytes);
    ret = read_data_block (lba_buf, inode_blk_addr);

    uint8_t *inode_offset
        = ((uint8_t *)lba_buf) + get_inode_byte_offset_in_block (inum);

    memcpy (inode_offset, inode,
            sizeof (struct s2fs_inode)); // copy new inode into read blk

    ret = zns_udevice_write (
        g_my_dev, inode_blk_addr, lba_buf,
        g_my_dev->lba_size_bytes); // write the updated lba blk back

    free (lba_buf);
  }
  return ret;
}

int
alloc_inode (uint64_t &inum)
{

  int ret = -ENOSYS;
  // get inode_bitmap

 std::vector<uint8_t> inode_bitmap;
  inode_bitmap.resize (fs_my_dev->inode_bitmap_size);

  {

    std::lock_guard<std::mutex> lock (bitmap_mut);
   ret = zns_udevice_read (g_my_dev, fs_my_dev->inode_bitmap_address,
                            inode_bitmap.data (),
                            fs_my_dev->inode_bitmap_size);
    bool set = false;
    for (uint i = 0; i < fs_my_dev->total_inodes; i++)
      {
        uint8_t inode_bm_map = inode_bitmap[i / 8];
        uint8_t index = i % 8;
        uint8_t bitmask = 1 << index;

        if (!(inode_bm_map & bitmask))
          {
           inum = i;
            inode_bitmap[i / 8] = inode_bm_map | bitmask;
            set = true;
            break;
          }
      }

    ret = zns_udevice_write (g_my_dev, fs_my_dev->inode_bitmap_address,
                             inode_bitmap.data (),
                             fs_my_dev->inode_bitmap_size);
    if (!set)
      return -1;
  }
  return ret;
}

int
free_inode (uint64_t inum)
{
  int ret = -ENOSYS;

  std::vector<uint8_t> inode_bitmap;
  inode_bitmap.resize (fs_my_dev->inode_bitmap_size);

  {
    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = zns_udevice_read (g_my_dev, fs_my_dev->inode_bitmap_address,
                            inode_bitmap.data (),
                            fs_my_dev->inode_bitmap_size);

    uint8_t inode_bm8 = inode_bitmap[inum / 8];
    uint index = inum % 8;
    uint8_t bitmask = 1 << index;
    inode_bitmap[inum / 8] = inode_bm8 & (~bitmask);

    ret = zns_udevice_write (g_my_dev, fs_my_dev->inode_bitmap_address,
                             inode_bitmap.data (),
                             fs_my_dev->inode_bitmap_size);
  }
  return ret;
}

int
free_data_blocks (std::vector<uint64_t> dbs)
{
  int ret = -ENOSYS;

  // convert db addresses to db numbers
  for (uint i = 0; i < dbs.size (); i++)
    dbs[i] = (dbs[i] - fs_my_dev->data_address) / g_my_dev->lba_size_bytes;

  std::vector<uint8_t> data_bitmap;
  data_bitmap.resize (fs_my_dev->data_bitmap_size);
  {
    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = zns_udevice_read (g_my_dev, fs_my_dev->data_bitmap_address,
                            data_bitmap.data (), fs_my_dev->data_bitmap_size);

    for (uint i = 0; i < dbs.size (); i++)
      {
        uint dn = dbs[i];
        uint8_t data_bm8 = data_bitmap[dn / 8];
        uint index = dn % 8;
        uint8_t bitmask = 1 << index;
        data_bitmap[dn / 8] = data_bm8 & (~bitmask);
      }

    ret = zns_udevice_write (g_my_dev, fs_my_dev->data_bitmap_address,
                             data_bitmap.data (), fs_my_dev->data_bitmap_size);
  }
  return ret;
}

int
alloc_data_blocks (uint64_t size, std::vector<uint64_t> &fbs)
{

  int ret = -ENOSYS;
  std::vector<uint64_t> dnums;
  uint32_t tot_blks = ceil_lba (size) / g_my_dev->lba_size_bytes;
  {
    std::lock_guard<std::mutex> lock (bitmap_mut);

    // read datablock bitmap
    std::vector<uint8_t> data_bitmap;
    data_bitmap.resize (fs_my_dev->data_bitmap_size);

   ret = zns_udevice_read (g_my_dev, fs_my_dev->data_bitmap_address,
                            data_bitmap.data (), fs_my_dev->data_bitmap_size);

    for (uint i = 0; i < fs_my_dev->total_data_blocks; i++)
      {
        uint8_t data_bm8 = data_bitmap[i / 8];
        uint8_t index = i % 8;
        uint8_t bitmask = 1 << index;

        if (!(data_bm8 & bitmask))
          {
            data_bitmap[i / 8] = data_bm8 | bitmask;
            dnums.push_back (i);
          }

        if (dnums.size () == tot_blks)
          break;
      }

    // when not enough data blocks
    if (tot_blks != dnums.size ())
      return -1;

    for (uint i = 0; i < dnums.size (); i++)
      fbs.push_back (fs_my_dev->data_address
                     + (dnums[i] * g_my_dev->lba_size_bytes));

    ret = zns_udevice_write (g_my_dev, fs_my_dev->data_bitmap_address,
                             data_bitmap.data (), fs_my_dev->data_bitmap_size);
  }
  return ret;
};

// initialize the root inode
int
init_iroot ()
{

  int ret = -ENOSYS;
  iroot = (struct s2fs_inode *)malloc (sizeof (struct s2fs_inode));

  // allocating inode bitmap 0
  uint64_t ir_inum;
  alloc_inode (ir_inum);

  if (ir_inum != 0)
    std::cout << "Something has gone wrong!" << std::endl;

  std::vector<uint64_t> fbs;

  // get two free datablocks (one for dlb, one for root dir entries)
  alloc_data_blocks ((g_my_dev->lba_size_bytes) * 2, fbs);

  uint32_t dir_rows = fs_my_dev->dirb_rows;
  uint32_t dlb_rows = fs_my_dev->dlb_rows;

  std::vector<dir_entry> root_dir;
  init_dir_data (root_dir, dir_rows);

  std::vector<data_lnb_row> root_dlb (dlb_rows, { (uint64_t)-1, 0 });
  root_dlb[0].address = fbs[1];
  root_dlb[0].size = g_my_dev->lba_size_bytes;

  write_data_block (root_dlb.data (), fbs[0]);
  write_data_block (root_dir.data (), fbs[1]);

  iroot->start_addr = fbs[0];
  iroot->file_size = g_my_dev->lba_size_bytes;
  iroot->i_type = 1; // directory

  std::time_t curr_time = std::time (nullptr);
  iroot->i_ctime = curr_time;
  iroot->i_mtime = curr_time;

  // write root inode
  ret = write_inode (fs_my_dev->inode_bitmap_address, iroot);
  return ret;
}

/*
 *
 * using addresses, create contiguous blocks for block operations
 *
 * [0, 4096, 8192, 41952]  ----> [{addr: 0, size: 12228}, {addr: 41952, size:
 * 4096}]
 *
 */
void
get_cg_blocks (std::vector<uint64_t> addr_list,
               std::vector<data_lnb_row> &cg_addrs)
{

  cg_addrs.push_back ({ addr_list[0], g_my_dev->lba_size_bytes });

  for (uint i = 1; i < addr_list.size (); i++)
    {

     int sz = cg_addrs.size ();
      int lst_index = sz - 1;

      if (cg_addrs[lst_index].address + cg_addrs[lst_index].size
          == addr_list[i])
        {
          cg_addrs[lst_index].size += g_my_dev->lba_size_bytes;
        }
      else
        {
          cg_addrs.push_back ({ addr_list[i], g_my_dev->lba_size_bytes });
        }
    }
}

/* gets all the data block addresses associated with a file
 *
 * dlb_addr <- starting data link block for the inode
 * inode_db_addr_list <- vector where to insert all the data block addresses
 * for an inode
 *
 * a_dlb <- insert data link block into list
 * offset <- the address offset from when to start including link blocks
 * cur_offset <- the current offset of the dlb_addr
 * size <- block size of the addresses
 *
 */
int
get_read_db_addrs (uint64_t dlb_addr, std::vector<uint64_t> &read_addrs,
                   bool a_dlb, uint64_t offset, uint64_t size)
{

  uint64_t c_dlb_addr = dlb_addr;
  uint64_t cur_offset = 0;
  uint64_t end_offset = offset + size;
  int ret = -ENOSYS;

  while (cur_offset < end_offset)
    {
      std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
      ret = read_data_block (dlb.data (), c_dlb_addr);

      if (a_dlb)
        read_addrs.push_back (c_dlb_addr);

      for (uint i = 0; i < dlb.size () - 1; i++)
        {
          uint64_t address = dlb[i].address;
          uint64_t size = dlb[i].size;

          if (cur_offset >= end_offset || dlb[i].address == (uint64_t)-1)
            break;

          // insert blocks we have to read
          if (cur_offset + size > offset)
            read_addrs.push_back (address);

          cur_offset += size;
        }

      c_dlb_addr = dlb[fs_my_dev->dlb_rows - 1].address;

      if (c_dlb_addr == (uint64_t)-1 && cur_offset < end_offset)
        return -1;
    }

  return ret;
}

// reads data sequentially from the given starting address (the address has to
// be a link data block)
int
read_data (uint64_t st_dlb_addr, void *buf, size_t size, uint64_t offset)
{

  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  std::vector<uint64_t> read_addrs;   // blocks to read
  std::vector<data_lnb_row> cg_addrs; // contiguous block ops

        int ret = -ENOSYS;
  // get contigous blocks in the data sequnce block
  get_read_db_addrs (st_dlb_addr, read_addrs, false, floor_lba (offset),
                     ceil_lba (offset + size));
  get_cg_blocks (read_addrs, cg_addrs);

  // read all data into temp buffer
  uint64_t rsize = ceil_lba (offset + size) - floor_lba (offset);

  uint8_t *tbuf = (uint8_t *)malloc (rsize);
  uint8_t *fbuf = tbuf;

  for (uint i = 0; i < cg_addrs.size (); i++)
    {
      uint64_t c_rsize = cg_addrs[i].size;
      ret = zns_udevice_read (g_my_dev, cg_addrs[i].address, tbuf, c_rsize);
      tbuf += c_rsize;
    }

  memcpy (buf, fbuf + offset, size);
  free (fbuf);
  return ret;
}

// get the inode's last data link block
uint64_t
get_lst_dlb (uint64_t st_dlb_addr)
{
  uint64_t c_dlb_addr = st_dlb_addr;

  while (true)
    {
      std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
      read_data_block (dlb.data (), c_dlb_addr);

      if (dlb[fs_my_dev->dlb_rows - 1].address == (uint64_t)-1)
        return c_dlb_addr;

      c_dlb_addr = dlb[fs_my_dev->dlb_rows - 1].address;
    }
}

// insert data block addresses into an indirect block's entries
int
insert_db_addrs_in_dlb (uint64_t lst_dlb_addr, std::vector<uint64_t> db_addrs,
                        size_t size)
{
  int ret = -ENOSYS;

  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  uint64_t c_dlb_addr = lst_dlb_addr;
  uint t_size = size;

  std::vector<uint64_t> dlb_dbs; // list of dnums alloc during func

  while (db_addrs.size () != 0)
    {
      ret = read_data_block (dlb.data (), c_dlb_addr);

      // insert data blocks into cur indirect block
      for (uint i = 0; i < dlb.size () - 1; i++)
        {
          // insert when row is free
          if (dlb[i].address == (uint64_t)-1)
            {
              uint b_size = g_my_dev->lba_size_bytes < t_size
                                ? g_my_dev->lba_size_bytes
                                : t_size;
              dlb[i] = { db_addrs[0], b_size };
              db_addrs.erase (db_addrs.begin ());
              t_size -= b_size;
            }

          if (db_addrs.size () == 0)
            {
              ret = write_data_block (dlb.data (), c_dlb_addr);
              break;
            }
        }

      if (db_addrs.size () == 0)
        break;

      // create an indirect block to insert data blocks
      std::vector<uint64_t> fb_list;
      ret = alloc_data_blocks (g_my_dev->lba_size_bytes, fb_list);

      // no space left
      if (ret == -1)
        {
          free_data_blocks (dlb_dbs);
          return ret;
        }

      // initialize a new dlb (indirect block)
      dlb[fs_my_dev->dlb_rows - 1].address = fb_list[0];
      ret = write_data_block (dlb.data (), c_dlb_addr);
      c_dlb_addr = fb_list[0];
      dlb_dbs.push_back (fb_list[0]);
      ret = init_dlb_data_block (fb_list[0]);
    }

  return ret;
}

/*
 * size - size of the buffer to write
 * w_blks - list of addresses where the buffer will be written to
 * free - either use fresh addresses to write data, or use addresses in w_blks
 *
 * This function either gets free blocks, or writes to blocks in the w_blks
 * list
 */
int
write_to_data_blocks (void *buf, uint64_t size, std::vector<uint64_t> &w_blks,
                      bool free)
{
  int ret = -ENOSYS;

  std::vector<data_lnb_row> baddr_writes;

  if (free)
    ret = alloc_data_blocks (size, w_blks);
  else
    ret = 0;

  // cannot write buffer
  if (ret == -1)
    return ret;

  get_cg_blocks (w_blks, baddr_writes);

  uint tmp_size = size;
  uint8_t *t_buf = (uint8_t *)buf;

  // writing to all blocks
  for (uint i = 0; i < baddr_writes.size (); i++)
    {

      int c_size
          = baddr_writes[i].size <= tmp_size ? baddr_writes[i].size : tmp_size;
      // aligning with lba size bytes
      std::vector<uint8_t> w_buf (baddr_writes[i].size);
      mempcpy (w_buf.data (), t_buf, c_size);

      ret = zns_udevice_write (g_my_dev, baddr_writes[i].address,
                               w_buf.data (), baddr_writes[i].size);
      t_buf += c_size;
      tmp_size -= c_size;
    }

  return ret;
}

/**
 * if 0|----------offset|------------offset+size|------|filesize
 *
 * overwrites file when offset + size_of_write < filesize
 *
 */

int
ow_write (void *buf, uint64_t dlb_address, uint64_t offset, uint64_t size)
{
  int ret = -ENOSYS;
  uint64_t aligned_offset = floor_lba (offset);
  uint64_t aligned_size = ceil_lba (offset + size);

  std::vector<uint64_t> w_blks;
  get_read_db_addrs (dlb_address, w_blks, false, aligned_offset, aligned_size);

  std::vector<data_lnb_row> cg_addrs;
  get_cg_blocks (w_blks, cg_addrs);

  void *ow_buf = malloc (aligned_size);
  uint8_t *tbuf = (uint8_t *)ow_buf;

  for (uint i = 0; i < cg_addrs.size (); i++)
    {
      uint64_t c_rsize = cg_addrs[i].size;
      ret = zns_udevice_read (g_my_dev, cg_addrs[i].address, tbuf, c_rsize);
      tbuf += c_rsize;
    }

  tbuf = (uint8_t *)ow_buf;
  memcpy (tbuf + offset, buf, size);
  ret = write_to_data_blocks (ow_buf, aligned_size, w_blks, false);

  free (ow_buf);
  return ret;
}

/*
 * append file write
 *
 * Structure of every file in zns device
 *
 * Inode -> indirect block ----> data block
 *                         ----> data block
 *                         ----> data block
 *                         ----> data block
 *                         -----> indirect block -----> data block
 *
 * Every inode points to an indirect block, every row/entry in indirect block
 * points to a data block except the last row/entry. The last entry is reserved
 * for a an indirect block to handle increasing file sizes
 *
 * The function below:
 * - gets the last indirect block
 * - writes data into free data blocks
 * - links these db addresses into the indirect block
 */
int
append_write (struct s2fs_inode inode, uint64_t st_dlb_addr, void *buf,
              size_t size)
{
  int ret = -ENOSYS;
  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  std::vector<uint64_t> free_block_list;

  // get the last data link block of the inode
  uint64_t lst_dlb_addr = get_lst_dlb (st_dlb_addr);
  ret = read_data_block (dlb.data (), lst_dlb_addr);

  // check if the last filled data block is partially filled
  if (inode.file_size % g_my_dev->lba_size_bytes != 0)
    {
      // get partially filled block entry
      uint parblock = 0;
      for (uint i = 0; i < dlb.size (); i++)
        {
          if (dlb[i].size < g_my_dev->lba_size_bytes)
            {
              parblock = i;
              break;
            }
        }

      uint offset = dlb[parblock].size;
      uint cop_size = g_my_dev->lba_size_bytes - offset;
      cop_size = cop_size < size ? cop_size : size;

      write_pf_data_block (buf, dlb[parblock].address, offset, cop_size);
      size_t tsize = size - cop_size;

      // update dlb
      dlb[parblock].size += cop_size;
      write_data_block (dlb.data (), lst_dlb_addr);

      // no more data to append
      if (tsize == 0)
        return 0;

      uint8_t *t_buf = ((uint8_t *)buf) + cop_size;

      std::vector<uint64_t> w_blks;
      ret = write_to_data_blocks (t_buf, tsize, w_blks, true);
      if (ret == -1)
        return ret;

      ret = insert_db_addrs_in_dlb (lst_dlb_addr, w_blks, tsize);
      if (ret == -1)
        {
          free_data_blocks (w_blks);
          return ret;
        }
    }
  else
    {
      std::vector<uint64_t> w_blks;
      ret = write_to_data_blocks (buf, size, w_blks, true);

      if (ret == -1)
        return ret;
      ret = insert_db_addrs_in_dlb (lst_dlb_addr, w_blks, size);
      if (ret == -1)
        {
          free_data_blocks (w_blks);
          return ret;
        }
    }
  return ret;
}

// init the file system
int
s2fs_init (struct user_zns_device *my_dev)
{
  int ret = -ENOSYS;
  uint64_t tot_lba, inode_bmap_byte_size, data_bmap_byte_size;
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
  inode_bmap_byte_size = ceil_byte (_t_x) / 8;
  inode_bmap_byte_size = ceil_lba (inode_bmap_byte_size);

  inode_bmap_buf = malloc (inode_bmap_byte_size);
  memset (inode_bmap_buf, 0, inode_bmap_byte_size);

  fs_my_dev->total_data_blocks
      = fs_my_dev->total_data_blocks
        - inode_bmap_byte_size / g_my_dev->lba_size_bytes;

  fs_my_dev->inode_bitmap_address = 0x00;
  fs_my_dev->inode_bitmap_size = inode_bmap_byte_size;
  ret = zns_udevice_write (my_dev, fs_my_dev->inode_bitmap_address,
                           inode_bmap_buf, fs_my_dev->inode_bitmap_size);

  // write data bitmap
  fs_my_dev->data_bitmap_address
      = fs_my_dev->inode_bitmap_address + fs_my_dev->inode_bitmap_size;
  uint64_t data_bmap_bit_size = fs_my_dev->total_data_blocks;
  data_bmap_byte_size = ceil_byte (data_bmap_bit_size) / 8;
  data_bmap_byte_size = ceil_lba (data_bmap_byte_size);

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
  fs_my_dev->total_data_blocks
      = fs_my_dev->total_data_blocks
        - ((sizeof (struct s2fs_inode) * _t_x) / g_my_dev->lba_size_bytes);

  // set up dir block structure and data link block structure
  fs_my_dev->dlb_rows
      = g_my_dev->lba_size_bytes / sizeof (struct data_lnb_row);
  fs_my_dev->dirb_rows = g_my_dev->lba_size_bytes / sizeof (struct dir_entry);

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

int
s2fs_write_to_inode (void *buf, uint64_t inum, uint64_t offset, size_t size)
{
  struct s2fs_inode inode;
  read_inode (inum, &inode);

  int ret = -ENOSYS;

  // check if write is just an append
  if (offset == inode.file_size || offset == (uint64_t)-1)
    {
      //std::cout << inode.file_size << " " << inode.file_name << std::endl;
      ret = append_write (inode, inode.start_addr, buf, size);
      inode.file_size += size;
      write_inode (inum, &inode);
    }
  else
    {

      // file overwrite
      if (offset + size < inode.file_size)
        {
          ret = ow_write (buf, inode.start_addr, offset, size);
        }
      else
        {
          // partial overwrite
          uint64_t ow_size = inode.file_size - offset;
          ret = ow_write (buf, inode.start_addr, offset, ow_size);

          // append
          uint8_t *t_buf = ((uint8_t *)buf) + ow_size;
          size -= (inode.file_size - offset);
          ret = append_write (inode, inode.start_addr, t_buf, size - ow_size);

          inode.file_size += size - ow_size;
          write_inode (inum, &inode);
        }
    }
  return ret;
}

int
s2fs_open (std::string filename, int oflag, mode_t mode)
{
  int ret = -ENOSYS;

  uint64_t inum;
  struct s2fs_inode inode;
  ret = get_file_inode (filename, &inode, inum);

  if (ret == -1 || inode.i_type == 1)
    {
      return -1;
    }

  {
    // preventing multiple threads from getting the same fd_num
    std::lock_guard<std::mutex> lock (fd_mut);
    const uint32_t rfd = g_fd_count;
    g_fd_count += 1;
    struct fd_info fd_i = { filename, rfd, inum, 0, mode };
    fd_table.insert (std::make_pair (rfd, fd_i));

    return rfd;
  }
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
s2fs_write (int fd, void *buf, size_t size, uint64_t offset)
{
  // every write has to be from +8 bytes as there is metadata
  int ret = -ENOSYS;
  struct fd_info inode_info;
  if (fd_table.count (fd) > 0)
    inode_info = fd_table[fd];
  else
    return -1;

  ret = s2fs_write_to_inode (buf, inode_info.inode_id, offset, size);
  return ret;
}

// implemented without lseek  // perform errors checks with inode file size?
int
s2fs_read (int fd, void *buf, size_t size, uint64_t offset, uint64_t &san_size)
{
  int ret = -ENOSYS;
  uint64_t inode_id;
  struct s2fs_inode inode;

  struct fd_info inode_info;
  if (fd_table.count (fd) > 0)
    inode_info = fd_table[fd];
  else
    return -1;

  inode_id = inode_info.inode_id;
  read_inode (inode_id, &inode);

  // sanitize size
  san_size = size;
  if (offset + size > inode.file_size){
          san_size = inode.file_size - offset;
  }

  // sanitize offset
  if (offset > inode.file_size){
        return -1;
  }

  ret = read_data (inode.start_addr, buf, san_size, offset);
  return ret;
}

// Initializes Inode struct
s2fs_inode
init_inode (std::string file_name, uint64_t start_addr, int file_size,
            bool if_dir)
{

  s2fs_inode new_inode;
  strncpy (new_inode.file_name, file_name.c_str (),
           sizeof (new_inode.file_name) - 1);
  new_inode.file_name[sizeof (new_inode.file_name) - 1] = '\0';
  new_inode.start_addr = start_addr;
  new_inode.file_size = file_size;
  new_inode.i_type = if_dir ? 1 : 0;
  new_inode.blocks = if_dir ? 2 : 1;
  return new_inode;
}

// Path traversal function
std::vector<std::string>
path_to_vec (std::string path)
{ // returns a vec with path contents

  std::vector<std::string> path_contents;
  std::stringstream ss (path);
  std::string directory;

  path_contents.push_back ("/"); // add root dir

  while (std::getline (ss, directory, '/'))
    {
      if (!directory.empty ())
        {
          path_contents.push_back (directory);
        }
    }

  return path_contents;
}

int
get_file_inode (std::string path, struct s2fs_inode *inode, uint64_t &inum)
{
  std::vector<std::string> path_contents = path_to_vec (path);

  uint64_t next_dir_inum;

  next_dir_inum = 0; // root inum number
  bool found = false;

  // get root inode
  if (path_contents.size () == 1)
    {
      inum = 0;
      found = true;
    }

  for (uint i = 0; i < path_contents.size () - 1; i++)
    {
      read_inode (next_dir_inum, inode);
      uint64_t cdir_saddr = inode->start_addr;
      uint16_t cdir_size = inode->file_size;

      std::vector<dir_entry> dir;
      dir.resize (cdir_size / sizeof (dir_entry));

      read_data (cdir_saddr, dir.data (), cdir_size, 0);
      found = false;

      // Find inode num of next in path
      for (uint j = 0; j < dir.size (); j++)
        {
          if (dir[j].entry_name == path_contents[i + 1])
            {
              next_dir_inum = dir[j].inum;
              inum = next_dir_inum;
              found = true;
              break;
            }
        }

      if (!found)
        break;
    }

  if (!found)
    return -1;

  read_inode (inum, inode);
  return 0;
}

int
get_dbnums_list_of_file (std::vector<uint64_t> &dnums_list,
                         uint64_t file_saddr, uint64_t file_size)
{

  int ret = -ENOSYS;
  std::vector<uint64_t> inode_db_addr_list;

  for (uint i = 0; i < inode_db_addr_list.size (); i++)
    {
      uint64_t dnum = (inode_db_addr_list[i] - fs_my_dev->data_address)
                      / g_my_dev->lba_size_bytes;

      dnums_list.push_back (dnum);
    }
  return ret;
}

std::string
get_pdir_path (std::string path)
{
  uint last_slash = path.find_last_of ("/\\");

  std::string pdir_path = path.substr (0, last_slash);

  if (last_slash == 0)
    {
      pdir_path = "/";
    }
  return pdir_path;
}

std::string
get_file_name (std::string path)
{

  uint last_slash = path.find_last_of ("/\\");
  std::string file_name = path.substr (last_slash + 1, path.size ());
  return file_name;
}

void
add_to_dir (uint64_t inum, std::string file_name, bool type,
            std::vector<dir_entry> &p_dir)
{
  dir_entry dir_entry;
  dir_entry.inum = inum;
  strncpy (dir_entry.entry_name, file_name.c_str (),
           sizeof (dir_entry.entry_name) - 1);
  dir_entry.entry_name[sizeof (dir_entry.entry_name) - 1]
      = '\0'; // have to test this conversion

  if (type)
    dir_entry.entry_type = 1;
  else
    dir_entry.entry_type = 0;

  // Add new dir_entry to Dir_data
  bool set = false;
  for (uint i = 0; i < p_dir.size (); i++)
    {
      if (p_dir[i].inum == (uint64_t)-1)
        {
          p_dir[i] = dir_entry;
          set = true;
          break;
        }
    }

  if (!set)
    p_dir.push_back (dir_entry);

  if (p_dir.size () != ceil_dirb_rows (p_dir.size ()))
    init_dir_data (p_dir, ceil_dirb_rows (p_dir.size ()));
}

void
remove_from_dir (uint64_t inum, std::vector<dir_entry> &p_dir)
{
  for (uint i = 0; i < p_dir.size (); i++)
    {
      if (p_dir[i].inum == inum)

        {
          p_dir.erase (p_dir.begin () + i);
          break;
        }
    }

  if (p_dir.size () != ceil_dirb_rows (p_dir.size ()))
    init_dir_data (p_dir, ceil_dirb_rows (p_dir.size ()));
}

int
__create_file (uint64_t inum, std::string file_name)
{
  int ret = -ENOSYS;

  s2fs_inode new_inode;

  // get start address of file
  std::vector<uint64_t> t_free_block_list;
  ret = alloc_data_blocks (g_my_dev->lba_size_bytes, t_free_block_list);
  ret = init_dlb_data_block (t_free_block_list[0]);

  new_inode = init_inode (file_name, t_free_block_list[0], 0, false);
  ret = write_inode (inum, &new_inode);

  return ret;
}

int
__create_dir (uint64_t inum, std::string file_name)
{
  int ret = -ENOSYS;

  s2fs_inode new_inode;

  // get start address of file
  std::vector<uint64_t> t_free_block_list;
  ret = alloc_data_blocks (g_my_dev->lba_size_bytes * 2, t_free_block_list);

  ret = init_dlb_data_block (t_free_block_list[0]);

  std::vector<dir_entry> dirb;
  init_dir_data (dirb, (g_my_dev->lba_size_bytes) / sizeof (dir_entry));
  write_data_block (dirb.data (), t_free_block_list[1]);

  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  read_data_block (dlb.data (), t_free_block_list[0]);

  dlb[0].address = t_free_block_list[1];
  dlb[0].size = g_my_dev->lba_size_bytes;
  write_data_block (dlb.data (), t_free_block_list[0]);

  new_inode = init_inode (file_name, t_free_block_list[0],
                          g_my_dev->lba_size_bytes, true);

  ret = write_inode (inum, &new_inode);

  return ret;
}

int
create_file (std::string path, bool if_dir)
{

  int ret = -ENOSYS;
  std::string file_name = get_file_name (path);

  // check if file exists or not
  struct s2fs_inode inode;
  uint64_t t_inum;
  ret = get_file_inode (path, &inode, t_inum);
  if (ret == 0)
    return 0;

  // Allocate inode block
  uint64_t i_num;
  ret = alloc_inode (i_num);

  if (ret == -1)
    return ret;

  // add entry to pdir
  ret = update_dir_data (get_pdir_path (path), file_name, i_num, if_dir, true);
  if (ret == -1)
    return ret;

  if (if_dir)
    __create_dir (i_num, file_name);
  else
    __create_file (i_num, file_name);

  return ret;
}

int
update_dir_data (std::string dir_path, std::string file_name, uint64_t i_num,
                 bool if_dir, bool add_entry)
{

  int ret = -ENOSYS;

  // get dir inode
  struct s2fs_inode inode;
  uint64_t d_inum;
  ret = get_file_inode (dir_path, &inode, d_inum);

  // create dir when parent directory doesn't exist
  if (ret == -1)
    {
      ret = create_file (dir_path, true);
      // not enough space to create file
      if (ret == -1)
        return ret;
      ret = get_file_inode (dir_path, &inode, d_inum);
    }

  uint64_t dir_saddr = inode.start_addr;
  uint16_t dir_size = inode.file_size;

  // read dir data
  std::vector<dir_entry> dir;
  dir.resize (dir_size / sizeof (dir_entry));
  ret = read_data (dir_saddr, dir.data (), dir_size, 0);

  if (add_entry)
    add_to_dir (i_num, file_name, if_dir, dir);
  else
    remove_from_dir (i_num, dir);

  // release dblks used by old dir data
  std::vector<data_lnb_row> inode_db_addr_list;
  std::vector<uint64_t> db_addrs;
  ret = get_read_db_addrs (dir_saddr, db_addrs, true, 0, dir_size);
  free_data_blocks (db_addrs); // setting old blks false

  // write new dir data
  std::vector<uint64_t> free_block_list;
  ret = alloc_data_blocks (g_my_dev->lba_size_bytes, free_block_list);
  inode.start_addr = free_block_list[0];
  init_dlb_data_block (free_block_list[0]);
  ret = append_write (inode, free_block_list[0], dir.data (),
                      dir.size () * sizeof (dir_entry));
  inode.file_size = dir.size () * sizeof (dir_entry);
  write_inode (d_inum, &inode);

  return ret;
}

int
delete_file (std::string path, bool u_pdir)
{
  int ret = -ENOSYS;
  struct s2fs_inode inode;
  uint64_t inum;

  ret = get_file_inode (path, &inode, inum);
  if (ret == -1)
    return ret;

  std::string file_name = get_file_name (path);

  // remove entry from parent directory
  if (u_pdir)
    ret = update_dir_data (get_pdir_path (path), file_name, inum, false,
                           false);
  free_inode (inum);

  // Data removal
  std::vector<uint64_t> dbs;
  get_read_db_addrs (inode.start_addr, dbs, true, 0, inode.file_size);
  free_data_blocks (dbs);

  return ret;
}

int
delete_dir (std::string path, bool u_pdir)
{

  int ret = -ENOSYS;
  std::string dir_name = get_file_name (path);

  // Get file inode num
  struct s2fs_inode inode;
  uint64_t inum;
  std::vector<dir_entry> dir;

  ret = get_file_inode (path, &inode, inum);

  if (ret == -1)
    return ret;

  std::string dir_path;

  dir.resize (inode.file_size / sizeof (dir_entry));
  ret = read_data (inode.start_addr, dir.data (), inode.file_size, 0);

  // check if empty dir
  bool isEmpty = true;
  for (uint i = 0; i < dir.size (); i++)
    {
      if (dir[i].inum != (uint64_t)-1)
        {
          isEmpty = false;
          break;
        }
    }

  if (!isEmpty)
    {
      // delete all dir entries
      for (uint i = 0; i < dir.size (); i++)
        {
          std::string child_path = path + "/" + dir[i].entry_name;

          if (dir[i].entry_type == 1 && dir[i].inum != (uint64_t)-1)
            ret = delete_dir (child_path, false);

          if (dir[i].entry_type == 0 && dir[i].inum != (uint64_t)-1)
            ret = delete_file (child_path, false);
        }
    }

  ret = delete_file (path, false);

  if (u_pdir)
    update_dir_data (get_pdir_path (path), dir_name, inum, true, false);

  return ret;
}

int
s2fs_create_file (std::string path, bool if_dir)
{
  int ret;
  {
    std::lock_guard<std::mutex> lock (dir_mut);
    ret = create_file (path, if_dir);

    // add newline to the file
    struct s2fs_inode inode;
    uint64_t inum;
    
    // if (!if_dir){
    //     get_file_inode(path, &inode, inum);

    //     if (inode.file_size != 0)
    //             return ret;
    //     std::vector<uint8_t> nl;
    //     nl.push_back(10);
    //     append_write(inode, inode.start_addr, nl.data(), 1);
    //     inode.file_size = 1;
    //     write_inode(inum, &inode);
    // }
  }
  return ret;
}

int
s2fs_delete (std::string path, bool if_dir)
{
  int ret;
  {
    std::lock_guard<std::mutex> lock (dir_mut);
    if (if_dir)
      ret = delete_dir (path, true);
    else
      ret = delete_file (path, true);
  }
  return ret;
}

bool
s2fs_file_exists (std::string path)
{
  struct s2fs_inode inode;
  uint64_t inum;

  {
    std::lock_guard<std::mutex> lock (dir_mut);
    int rt = get_file_inode (path, &inode, inum);
    if (rt == -1)
      return false;
    return true;
  }
}

int
s2fs_move_file (std::string src_path, std::string dest_path)
{

  int ret = -ENOSYS;

  struct s2fs_inode inode;
  uint64_t file_inum;
  {
    std::lock_guard<std::mutex> lock (dir_mut);
    ret = get_file_inode (src_path, &inode, file_inum);

    if (ret == -1)
      return ret;

    std::string src_file_name = get_file_name (src_path);
    std::string dest_file_name = get_file_name (dest_path);

    // remove from pdir at src
    ret = update_dir_data (get_pdir_path (src_path), src_file_name, file_inum,
                           false, false);
    ret = update_dir_data (get_pdir_path (dest_path), dest_file_name,
                           file_inum, false, true);

    // change file name in inode
    strncpy(inode.file_name, dest_file_name.c_str(), sizeof(dest_file_name));
    write_inode(file_inum, &inode);
  }
  return ret;
}

int
s2fs_get_file_size (std::string path, uint64_t &size)
{
  int ret = -ENOSYS;

  s2fs_inode inode;
  uint64_t inum;

  ret = get_file_inode (path, &inode, inum);

  if (ret == -1)
    return ret;
  size = inode.file_size;
  return ret;
}

int
s2fs_get_dir_children (std::string path, std::vector<std::string> *file_list)
{

  int ret = -ENOSYS;

  // Get dir inode num
  s2fs_inode inode;
  uint64_t inum;
  {
    std::lock_guard<std::mutex> lock (dir_mut);
    ret = get_file_inode (path, &inode, inum);

    if (ret == -1)
      return ret;

    /* Dir reading */
    std::vector<dir_entry> dir;
    dir.resize (inode.file_size / sizeof (dir_entry));
    ret = read_data (inode.start_addr, dir.data (), inode.file_size,
                     0); // read_data_from_dlb

    for (uint i = 0; i < dir.size (); i++)
      {
        if (dir[i].inum != (uint64_t)-1)
          {
            file_list->push_back (dir[i].entry_name);
          }
      }
  }
  return ret;
}
