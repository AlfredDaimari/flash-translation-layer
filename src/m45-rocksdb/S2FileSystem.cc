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
#include "rocksdb/env.h"
#include "rocksdb/file_system.h"
#include "rocksdb/io_status.h"
#include <cstdint>
#include <iostream>
#include <math.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <vector>

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
S2SequentialFile::S2SequentialFile (std::string path)
{
  this->fd = s2fs_open (path, 0, 0);
}
S2SequentialFile::~S2SequentialFile () { s2fs_close (this->fd); }

IOStatus
S2SequentialFile::Read (size_t n, const IOOptions &options, Slice *result,
                        char *scratch, IODebugContext *dbg)
{
  std::vector<char> buf (n);
  int ret = s2fs_read (this->fd, buf.data (), n, 0);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);

  result = new Slice (buf.data (), n);
  return IOStatus::OK ();
}

// check if you need to implement offset
IOStatus
S2SequentialFile::Skip (uint64_t n)
{
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
  int ret = s2fs_write (fd, (void *)data.data (), data.size (), 0);
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
  std::vector<char> buf (n);
  int ret = s2fs_read (this->fd, buf.data (), n, offset);
  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);

  result = new Slice (buf.data (), n);
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
}

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
  int ret = s2fs_create_file (this->_uri + fname, false);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);

  std::unique_ptr<S2SequentialFile> seq_ptr
      = std::make_unique<S2SequentialFile> (this->_uri + fname);

  result = (std::unique_ptr<FSSequentialFile> *)&seq_ptr;
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
  int ret = s2fs_create_file (this->_uri + fname, false);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  std::unique_ptr<S2RandomAccessFile> s2_ptr
      = std::make_unique<S2RandomAccessFile> (this->_uri + fname);

  result = (std::unique_ptr<FSRandomAccessFile> *)&s2_ptr;
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
  int ret = s2fs_create_file (this->_uri + fname, false);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);

  std::unique_ptr<S2WritableFile> s2_ptr
      = std::make_unique<S2WritableFile> (this->_uri + fname);

  result = (std::unique_ptr<FSWritableFile> *)&s2_ptr;
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
  std::string dir_path = this->_uri + name;
  int ret = s2fs_create_file (dir_path, true);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);

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
  std::string path = this->_uri + dirname;
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
  std::string op = this->_uri + db_path;
  output_path = &op;
  return IOStatus::OK ();
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
  std::string log_path = this->_uri + fname;
  s2fs_create_file (log_path, false);
  std::shared_ptr<Logger> s2_ptr = std::make_shared<S2Logger> ();
  result = &s2_ptr;
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
  std::string src_path = this->_uri + src;
  std::string target_path = this->_uri + target;

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
  std::string dir_path = this->_uri + dir;
  std::vector<std::string> children;

  int ret = s2fs_get_dir_children (dir_path, children);

  if (ret == -1)
    return IOStatus::IOError (__FUNCTION__);
  result = &children;
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
  std::string path = this->_uri + fname;
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
}

std::unordered_map<uint32_t, fd_info> fd_table;
uint32_t g_fd_count; // always points to the next available fd
std::mutex fd_mut;
std::mutex bitmap_mut; // mutex for when making changes to the bitmap

struct user_zns_device *g_my_dev;
struct fs_zns_device *fs_my_dev;
struct s2fs_inode *iroot;

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

uint64_t get_dnum_from_addr (uint64_t db_addr)
{
  return (db_addr - fs_my_dev->data_address)/g_my_dev->lba_size_bytes;
}
int
read_data_block (void *data_block, uint64_t address)
{
  int ret = zns_udevice_write (g_my_dev, address, data_block,
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
write_pf_data_block (void *buf, uint64_t address, uint32_t lba_offset)
{
  void *data_block = malloc (g_my_dev->lba_size_bytes);
  int ret = read_data_block (data_block, address);

  uint8_t *cp_offset = ((uint8_t *)buf) + lba_offset;
  uint size = g_my_dev->lba_size_bytes - lba_offset;
  memcpy (cp_offset, buf, size);

  ret = write_data_block (data_block, address);
  free (data_block);
  return ret;
}

// initialize a data block as a data link block
int
init_dlb_data_block (uint64_t address)
{
  std::vector<data_lnb_row> init_dlb (fs_my_dev->dlb_rows,
                                      { (uint64_t)-1, 0 });
  int ret = write_data_block (init_dlb.data (), address);
  return ret;
}

int
read_data_bitmap (uint8_t *data_bitmap)
{
  int ret
      = zns_udevice_read (g_my_dev, fs_my_dev->data_bitmap_address,
                          (void *)data_bitmap, fs_my_dev->data_bitmap_size);
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

  std::vector<uint8_t> data_bm_buf;
  data_bm_buf.resize (fs_my_dev->data_bitmap_size);
  {
    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = read_data_bitmap (&data_bm_buf[0]);

    for (uint i = 0; i < dnums.size (); i++)
      {
        uint dn = dnums[i];
        uint8_t data_bm_map = data_bm_buf[dn / 8];
        uint index = dn % 8;
        uint8_t bitmask = 1 << index;
        if (val)
          data_bm_buf[dn / 8] = data_bm_map | bitmask;
        data_bm_buf[dn / 8] = data_bm_map & (~bitmask);
      }

    ret = write_data_bitmap (&data_bm_buf[0]);
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
  std::vector<uint8_t> inode_bm_buf;
  inode_bm_buf.resize (fs_my_dev->inode_bitmap_size);

  int ret = -ENOSYS;
  {

    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = read_inode_bitmap (&inode_bm_buf[0]);

    for (uint i = 0; i < inums.size (); i++)
      {
        uint in = inums[i];
        uint8_t inode_bm_map = inode_bm_buf[in / 8];
        uint index = in % 8;
        uint8_t bitmask = 1 << index;

        if (val)
          inode_bm_buf[in / 8] = inode_bm_map | bitmask;
        inode_bm_buf[in / 8] = inode_bm_map & (~bitmask);
      }

    ret = write_inode_bitmap (&inode_bm_buf[0]);
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

  std::vector<uint8_t> inode_bm_buf;
  inode_bm_buf.resize (fs_my_dev->inode_bitmap_size);

  {

    std::lock_guard<std::mutex> lock (bitmap_mut);
    ret = read_inode_bitmap (&inode_bm_buf[0]);

    uint new_inode_id = 0;
    for (uint i = 0; i < fs_my_dev->total_inodes; i++)
      {
        uint8_t inode_bm_map = inode_bm_buf[i / 8];
        uint8_t index = i % 8;
        uint8_t bitmask = 1 << index;

        if (!(inode_bm_map & bitmask))
          {
            new_inode_id = i;
            inode_bm_buf[i / 8] = inode_bm_map | bitmask;
            break;
          }
      }

    ret = write_inode_bitmap (&inode_bm_buf[0]);

    if (new_inode_id == 0)
      return ret;

    inum = new_inode_id;
  }
  return ret;
}

int
get_free_data_blocks (uint64_t size, std::vector<uint64_t> &free_block_list)
{

  int ret = -ENOSYS;
  std::vector<uint64_t> free_dnum_list;
  uint32_t total_blocks_to_alloc
      = size / g_my_dev->lba_size_bytes
        + (size % g_my_dev->lba_size_bytes == 0 ? 0 : 1);

  {
    std::lock_guard<std::mutex> lock (bitmap_mut);

    // read datablock bitmap
    std::vector<uint8_t> data_bitmap;
    data_bitmap.resize (fs_my_dev->data_bitmap_size);

    read_data_bitmap ((uint8_t *)&data_bitmap[0]);

    // std::vector<bool> *vec_data_bitmap
    //     = static_cast<std::vector<bool> *> (data_bitmap);

    for (uint i = 0; i < fs_my_dev->total_data_blocks; i++)
      {
        uint8_t data_bm_map = data_bitmap[i / 8];
        uint8_t index = i % 8;
        uint8_t bitmask = 1 << index;

        if (!(data_bm_map & bitmask))
          free_dnum_list.push_back (i);

        if (free_dnum_list.size () == total_blocks_to_alloc)
          break;
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
        }
      update_data_bitmap (free_dnum_list, true);
      ret = 0;
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

  uint32_t dir_rows = fs_my_dev->dirb_rows;

  uint32_t dlb_rows = fs_my_dev->dlb_rows;
  std::vector<data_lnb_row> dlb_block (dlb_rows);
  // Set each element to {0, 0}
  for (auto &row : dlb_block)
    {
      row.address = (uint64_t) -1;
      row.size = 0;
    }
  std::vector<Dir_entry> root_dir_block (dir_rows);

  for (uint i = 0; i < root_dir_block.size (); i++)
    {
      root_dir_block[i].inum = (uint64_t) -1;
      root_dir_block[i].entry_type = 1; // dir = 1
      std::string f_name = "";
      const char *name_ptr = f_name.c_str ();
      strcpy (root_dir_block[i].entry_name, name_ptr);
    }

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
               std::vector<data_lnb_row> &cg_addr_list)
{

  cg_addr_list.push_back ({ addr_list[0], g_my_dev->lba_size_bytes });

  for (uint i = 1; i < addr_list.size (); i++)
    {

      int sz = cg_addr_list.size ();
      int lst_index = sz - 1;

      if (cg_addr_list[lst_index].address + cg_addr_list[lst_index].size
          == addr_list[i])
        {
          cg_addr_list[lst_index].size += g_my_dev->lba_size_bytes;
        }
      else
        {
          cg_addr_list.push_back ({ addr_list[i], g_my_dev->lba_size_bytes });
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
void
get_data_block_addrs (uint64_t dlb_addr,
                      std::vector<uint64_t> inode_db_addr_list, bool a_dlb,
                      uint64_t offset, uint64_t cur_offset, uint64_t size)
{

  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  read_data_block (dlb.data (), dlb_addr);

  if (a_dlb)
    inode_db_addr_list.push_back (dlb_addr);

  for (uint i = 0; i < fs_my_dev->dlb_rows - 1; i++)
    {
      if (dlb[i].address == (uint)-1 || cur_offset == size)
        {
          break;
        }
      if (cur_offset >= offset)
        inode_db_addr_list.push_back (dlb[i].address);
      cur_offset += g_my_dev->lba_size_bytes;
    }

  // check if there are more links
  if (dlb[fs_my_dev->dlb_rows - 1].address != (uint)-1 && cur_offset < size)
    {
      get_data_block_addrs (dlb[fs_my_dev->dlb_rows - 1].address,
                            inode_db_addr_list, a_dlb, offset, cur_offset,
                            size);
    }
}

// reads data sequentially from the given starting address (the address has to
// be a link data block)
int
read_data_from_dlb (uint64_t dlb_addr, void *buf, size_t size, uint64_t offset)
{

  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  std::vector<uint64_t> zns_read_list;
  std::vector<data_lnb_row> cg_addr_list;

  // reading the first link data sequence
  int ret = read_data_block (dlb.data (), dlb_addr);
  // get contigous blocks in the data sequnce block
  get_data_block_addrs (dlb_addr, zns_read_list, false, offset, 0, size);
  get_cg_blocks (zns_read_list, cg_addr_list);

  // read all data into temp buffer
  uint64_t rsize = size;

  if (size % g_my_dev->lba_size_bytes != 0)
    {
      uint64_t pad
          = g_my_dev->lba_size_bytes - (size % g_my_dev->lba_size_bytes);
      rsize += pad;
    }

  uint8_t *tbuf = (uint8_t *)malloc (rsize);

  for (uint i = 0; i < zns_read_list.size (); i++)
    {
      uint64_t c_rsize
          = cg_addr_list[i].size < rsize ? cg_addr_list[i].size : rsize;
      ret = zns_udevice_read (g_my_dev, cg_addr_list[i].address, tbuf,
                              c_rsize);
      rsize -= c_rsize;

      if (rsize == 0)
        break;
    }

  memcpy (buf, tbuf, size);
  free (tbuf);
  return ret;
}

// in the data_link_block get an empty row or row with partially filled block
int
dlb_get_pf_row (std::vector<data_lnb_row> data_lnb)
{
  for (uint i = 0; i < data_lnb.size () - 1; i++)
    {

      if (data_lnb[i].address == uint (-1))
        {
          return i;
        }

      // block is partially filled
      if (data_lnb[i].size < g_my_dev->lba_size_bytes)
        {
          return i;
        }
    }

  return -1;
}

// insert db_addr into dlb
int
insert_db_addrs_in_dlb (uint64_t dlb_addr, std::vector<uint64_t> db_addr_list,
                        size_t size)
{
  int ret = -ENOSYS;

  // get first free row
  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  ret = read_data_block (dlb.data (), dlb_addr);
  uint ufr = dlb_get_pf_row (dlb);

  uint t_size = size;

  for (uint i = ufr; i < dlb.size () - 1; i++)
    {
      uint b_size = g_my_dev->lba_size_bytes < t_size
                        ? g_my_dev->lba_size_bytes
                        : t_size;

      dlb[i] = { db_addr_list[0], b_size };
      t_size -= b_size;

      db_addr_list.erase (db_addr_list.begin ());
      if (db_addr_list.size () == 0)
        {
          break;
        }
    }

  // current data link block is full but free list has entries
  if (db_addr_list.size () != 0)
    {

      std::vector<uint64_t> t_free_block_list;
      ret = get_free_data_blocks (g_my_dev->lba_size_bytes, t_free_block_list);

      // could not get free dlb block to write
      if (ret == -1)
        {
          return ret;
        }

      uint64_t free_dlb_addr = t_free_block_list[0];
      // insert link block where remaining free blocks will be inserted
      dlb[fs_my_dev->dlb_rows - 1].address = t_free_block_list[0];

      // write updated link data block
      ret = write_data_block (dlb.data (), dlb_addr);
      ret = insert_db_addrs_in_dlb (free_dlb_addr, db_addr_list, t_size);
    }
  else
    {
      ret = write_data_block (dlb.data (), dlb_addr);
    }
  return ret;
}

/*
 * size - size of the buffer to write
 *
 * w_blks - inserts free block addresses or block addresses where to write to
 *
 * This function either gets free blocks, or writes to blocks in the list
 * w_blks
 */
int
write_to_data_blocks (void *buf, uint64_t size, std::vector<uint64_t> &w_blks,
                      bool free)
{
  int ret = -ENOSYS;

  std::vector<data_lnb_row> baddr_writes;

  if (free)
    ret = get_free_data_blocks (size, w_blks);
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

      int b_size
          = baddr_writes[i].size <= tmp_size ? baddr_writes[i].size : tmp_size;
      // aligning with lba size bytes
      void *w_buf = malloc (baddr_writes[i].size);
      mempcpy (w_buf, t_buf, b_size);

      ret = zns_udevice_write (g_my_dev, baddr_writes[i].address, w_buf,
                               baddr_writes[i].size);
      t_buf += b_size;
      tmp_size -= b_size;
    }

  return ret;
}

/**
 * if |<-0 --------- |<-offset ------------ |<-offset+size ---- |<-filesize
 *
 * overwrites file when offset + size_of_write < filesize
 *
 *
 */

int
overwrite_to_datablocks (void *buf, uint64_t dlb_address, uint64_t offset,
                         uint64_t size)
{
  int ret = -ENOSYS;
  uint64_t aligned_offset = floor_lba (offset);
  uint64_t aligned_size = ceil_lba (size);

  std::vector<uint64_t> w_blks;
  get_data_block_addrs (dlb_address, w_blks, false, aligned_offset, 0,
                        aligned_size);
  void *ow_buf = malloc (aligned_size);

  if (offset != aligned_offset)
    {
      void *lba_buf = malloc (g_my_dev->lba_size_bytes);
      ret = read_data_block (lba_buf, w_blks[0]);
      memcpy (ow_buf, lba_buf, offset - aligned_offset);
      free (lba_buf);
    }

  if (size != aligned_size)
    {
      void *lba_buf = malloc (g_my_dev->lba_size_bytes);
      ret = read_data_block (lba_buf, w_blks[-1]);
      uint8_t *t_buf = ((uint8_t *)ow_buf) + size;
      uint8_t *t_lba_buf
          = ((uint8_t *)lba_buf) + (size % g_my_dev->lba_size_bytes);
      memcpy (t_buf, t_lba_buf, aligned_size - size);
      free (lba_buf);
    }

  uint8_t *t_ow_buf = ((uint8_t *)ow_buf) + (offset - aligned_offset);
  memcpy (t_ow_buf, buf, size);
  ret = write_to_data_blocks (ow_buf, aligned_size, w_blks, false);
  free (ow_buf);

  return ret;
}

/*
 * apped file write
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
append_data_at_dlb (uint64_t dlb_addr, void *buf, size_t size)
{
  int ret = -ENOSYS;
  std::vector<data_lnb_row> dlb (fs_my_dev->dlb_rows);
  std::vector<uint64_t> free_block_list;

  ret = read_data_block (dlb.data (), dlb_addr);
  int pr_fr_dlb_row = dlb_get_pf_row (dlb);

  // when current dlb is full
  if (pr_fr_dlb_row == -1)
    {

      uint next_dlb_addr = dlb[fs_my_dev->dlb_rows - 1].address;

      // next dlb not initialised
      if (next_dlb_addr == (uint)-1)
        {

          std::vector<uint64_t> t_fr_block_list;
          ret = get_free_data_blocks (g_my_dev->lba_size_bytes,
                                      t_fr_block_list);

          if (ret == -1)
            {
              return -1;
            }

          dlb[fs_my_dev->dlb_rows - 1].address = t_fr_block_list[0];
          write_data_block (dlb.data (), dlb_addr);
          next_dlb_addr = t_fr_block_list[0];
        }

      ret = append_data_at_dlb (next_dlb_addr, buf, size);
    }

  // partially filled block
  else if (dlb[pr_fr_dlb_row].size < g_my_dev->lba_size_bytes)
    {
      uint offset = dlb[pr_fr_dlb_row].size;

      uint cop_size = g_my_dev->lba_size_bytes - offset;

      write_pf_data_block (buf, dlb[pr_fr_dlb_row].address, offset);
      size_t tsize = size - cop_size;

      // update dlb
      dlb[pr_fr_dlb_row].size = g_my_dev->lba_size_bytes;
      write_data_block (dlb.data (), dlb_addr);

      std::vector<uint64_t> w_blks;
      ret = write_to_data_blocks (buf, tsize, w_blks, true);

      if (ret == -1)
        return ret;

      ret = insert_db_addrs_in_dlb (dlb_addr, w_blks, tsize);

      if (ret == -1)
        {
          update_data_bitmap (w_blks, false);
          return ret;
        }
    }

  // when no partially filled block exists
  else
    {
      std::vector<uint64_t> w_blks;
      ret = write_to_data_blocks (buf, size, w_blks, true);

      if (ret == -1)
        return ret;

      ret = insert_db_addrs_in_dlb (dlb_addr, w_blks, size);

      if (ret == -1)
        {
          update_data_bitmap (w_blks, false);
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
  fs_my_dev->dirb_rows = g_my_dev->lba_size_bytes / sizeof (struct Dir_entry);

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
s2fs_write_to_inode_data_blocks (void *buf, uint64_t inum, uint64_t offset,
                                 size_t size)
{
  struct s2fs_inode *inode
      = (struct s2fs_inode *)malloc (sizeof (struct s2fs_inode));
  read_inode (inum, inode);

  int ret = -ENOSYS;

  // check if write is just an append
  if (offset == inode->file_size)
    {
      ret = append_data_at_dlb (inode->start_addr, buf, size);
    }
  else
    {

      // file overwrite
      if (offset + size < inode->file_size)
        {
          ret = overwrite_to_datablocks (buf, inode->start_addr, offset, size);
        }
      else
        {
          // partial overwrite and append

          // partial overwrite
          uint64_t ow_size = inode->file_size - offset;
          ret = overwrite_to_datablocks (buf, inode->start_addr, offset,
                                         ow_size);

          // append
          uint8_t *t_buf = ((uint8_t *)buf) + ow_size;
          size -= (inode->file_size - offset);
          ret = append_data_at_dlb (inode->start_addr, t_buf, size);
        }
    }
  return ret;
}

int
s2fs_open (std::string filename, int oflag, mode_t mode)
{
  int ret = -ENOSYS;

  // will fix later
  const uint32_t inode = 0; // ar23_get_inode (filename, oflag);

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
s2fs_write (int fd, void *buf, size_t size, uint64_t offset)
{
  // every write has to be from +8 bytes as there is metadata
  int ret = -ENOSYS;

  struct fd_info inode_info = fd_table[fd];
  s2fs_write_to_inode_data_blocks (buf, inode_info.inode_id, offset, size);

  return ret;
}

// implemented without lseek  // perform errors checks with inode file size?
int
s2fs_read (int fd, void *buf, size_t size, uint64_t offset)
{
  int ret = -ENOSYS;
  uint64_t inode_id;
  struct s2fs_inode *inode_buf
      = (struct s2fs_inode *)malloc (sizeof (struct s2fs_inode));

  struct fd_info inode_info = fd_table[fd];
  inode_id = inode_info.inode_id;

  read_inode (inode_id, inode_buf);

  ret = read_data_from_dlb (inode_buf->start_addr, buf, size, offset);
  return ret;
}

/*
std::vector<std::string> splitPath(const std::string& path) {
    std::vector<std::string> result;
    std::stringstream ss(path);
    std::string directory;

    while (std::getline(ss, directory, '/')) {
        if (!directory.empty()) {
            result.push_back(directory);
        }
    }

    return result;
}
*/

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

  int ret = -ENOSYS;

  // path should be a full path
  std::vector<std::string> path_contents
      = path_to_vec (path); // vector to store dir names

  uint32_t next_dir_inum;
  uint64_t next_inode_addr;
  s2fs_inode t_Inode;

  // Get root dir start addr
  uint32_t root_inum = 0; // should be def in init and global (fs_dev)

  for (int i = 0; i < path_contents.size (); i++)
    {

      /* Inode Reading */
      read_inode (root_inum, &t_Inode);
      uint64_t t_dir_saddr = t_Inode.start_addr;
      uint16_t t_dir_size = t_Inode.file_size;

      // Quit if file or last dir
      if (i == path_contents.size () - 1)
        {
          InodeResult ires;
          ires.inum = root_inum;
          ires.inode = t_Inode;
          return ires;
        }

      /* Dir reading */
      std::vector<Dir_entry> dir_entries;
      ret = read_data_from_dlb (t_dir_saddr, dir_entries.data (), t_dir_size,
                                0);

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
      root_inum = next_dir_inum;
    }
  InodeResult ires;
  ires.inum = next_dir_inum;
  ires.inode = t_Inode;

  return ires; // wont be used
}

int
update_inode_filesize (s2fs_inode inode, uint16_t delta, int sign)
{

  inode.file_size
      = (sign < 0) ? inode.file_size - delta : inode.file_size + delta;
}
/*
    update_path_sizes()

    Updates a inodes of all dirs in the path when a file/dir size changes

    delta: change in file_size

    sign: set to -1 if the file size is to be reduced

*/
int
update_path_isizes (std::vector<std::string> path_contents, uint16_t delta,
                    int sign)
{ // updating dir inodes of the file/dir size in the path
  // root > dir1 > dir2 > dir3 > file1(delta)
  int ret = -ENOSYS;
  std::string incr_path = "";

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
init_dir_data (std::vector<Dir_entry> &dir_entries)
{

  int ret = -ENOSYS;
  // Size of Dir_entry struct: 256 bytes
  // int num_de_lba = g_my_dev->lba_size_bytes/256; // num of dir entries per
  // lba
  dir_entries.resize (fs_my_dev->dirb_rows);

  // Access elements in the vector and initialize them if needed
  for (int i = 0; i < fs_my_dev->dirb_rows; ++i)
    {
      dir_entries[i].inum = 0;
      dir_entries[i].entry_type = 0;
      std::strcpy (dir_entries[i].entry_name, "");
    }

  return ret;
}

/*
    read_pdir_data()

    reads the pdir data

*/
int
read_pdir_data (std::string path, std::vector<Dir_entry> &dir_data_rows)
{

  int ret = -ENOSYS;
  size_t last_slash = path.find_last_of ("/\\"); // index of last slash
  std::string dir_path
      = path.substr (0, last_slash); // path of parent directory
  InodeResult ires = Get_file_inode (dir_path);
  s2fs_inode dir_inode = ires.inode;
  uint64_t dir_saddr = dir_inode.start_addr;
  uint16_t dir_size = dir_inode.file_size;

  /* Dir reading */
  ret = read_data_from_dlb (dir_saddr, dir_data_rows.data (), dir_size, 0);

  return ret;
}

int
get_dbnums_list_of_file (std::vector<uint64_t> &dnums_list,
                         uint64_t file_saddr, uint64_t file_size)
{

  int ret = -ENOSYS;
  std::vector<uint64_t> inode_db_addr_list;
  get_data_block_addrs (file_saddr, inode_db_addr_list, true, 0, 0,
                        file_size); //// check ???
  for (int i = 0; i < inode_db_addr_list.size (); i++)
    {
      uint64_t dnum = (inode_db_addr_list[i] - fs_my_dev->data_address)
                      / g_my_dev->lba_size_bytes;

      dnums_list.push_back (dnum);
    }
  return ret;
}

/*
    update_pdir_data()

    Updates dir data of the parent directory of path passed

    inum: inum of file/dir to be added or removed

    add_entry: set to true if entry to be added

*/
int
update_pdir_data (std::string path, uint64_t i_num, uint16_t if_dir,
                  bool add_entry)
{

  int ret = -ENOSYS;
  std::vector<std::string> path_contents = // vector to store dir names
      path_to_vec (path);
  size_t last_slash = path.find_last_of ("/\\"); // index of last slash

  std::string dir_path = path.substr (0, last_slash);
  if (last_slash == 0) {
    dir_path = "/" + dir_path;
  }             // path of parent directory
  std::string file_name = path_contents.back (); // file name

  // Update Parent dir data
  InodeResult ires = Get_file_inode (dir_path);
  s2fs_inode pdir_inode = ires.inode;
  uint64_t pdir_saddr = pdir_inode.start_addr;
  uint16_t pdir_size = pdir_inode.file_size;

  /* Dir reading */
  std::vector<Dir_entry> dir_data_rows;
  dir_data_rows.resize(pdir_size/sizeof(Dir_entry));
  ret = read_data_from_dlb (pdir_saddr, dir_data_rows.data (), pdir_size,
                            0); // read_data_from_dlb

  // DL /* dbs */ DL /* dbs */

  if (add_entry == true)
    {
      // Dir entry initialization
      Dir_entry dir_entry;
      dir_entry.inum = i_num;
      strncpy (dir_entry.entry_name, file_name.c_str (),
               sizeof (dir_entry.entry_name) - 1);
      dir_entry.entry_name[sizeof (dir_entry.entry_name) - 1]
          = '\0'; // have to test this conversion

      // entry type dir or file
      if (if_dir == 1)
        {
          dir_entry.entry_type = 1;
        }
      else
        {
          dir_entry.entry_type = 0;
        }
      // Add new dir_entry to Dir_data
      for (uint i = 0; i < dir_data_rows.size (); i++)
        {
          if (dir_data_rows[i].inum != 0)
            {
              dir_data_rows[i] = dir_entry;
            }
        }
    }
  else
    {
      // remove dir_entry => reset dir entry () remove the dir_entry
      for (uint i = 0; i < dir_data_rows.size (); i++)
        {
          if (dir_data_rows[i].inum == i_num)
            {
              std::strcpy (dir_data_rows[i].entry_name, "");
              dir_data_rows[i].entry_type = 0;
              dir_data_rows[i].inum = 0;
            }
        }
    }

  // Release dblks used by old dir data (release_inode_dblks)
  std::vector<data_lnb_row> inode_db_addr_list;
  std::vector<uint64_t> dnums_list;
  ret = get_dbnums_list_of_file (dnums_list, pdir_saddr, pdir_inode.file_size);
  update_data_bitmap (dnums_list, false); // setting old blks false

  std::vector<uint64_t> free_block_list;
  ret = get_free_data_blocks (g_my_dev->lba_size_bytes,
                              free_block_list); // only one dlb
  pdir_inode.start_addr = free_block_list[0];   // update dir_data saddr

  // Write dir_data again
  ret = append_data_at_dlb (free_block_list[0], &dir_data_rows,
                            sizeof (dir_data_rows));
  ret = get_dbnums_list_of_file (dnums_list, free_block_list[0],
                                 sizeof (dir_data_rows));
  update_data_bitmap (dnums_list, true); // setting new blks true

  // update all dirs in the path filesize
  uint16_t delta = 0; //////////////////////// write logic for delta calc??
  if (add_entry == true)
    {
      ret = update_path_isizes (path_contents, delta, 1);
    }
  else
    {
      ret = update_path_isizes (path_contents, delta, -1);
    }

  return ret;
}

/*
    create_file()

    creates a new file or dir

    if_dir: 1 if directory

*/
int
s2fs_create_file (std::string path, uint16_t if_dir)
{

  int ret = -ENOSYS;

  std::vector<std::string> path_contents = // vector to store dir names
      path_to_vec (path);
  std::string file_name = path_contents.back (); // file name

  // Allocate inode block
  uint64_t i_num = 1;
  ret = alloc_inode (i_num);

  // Create Inode block
  s2fs_inode new_inode;
  //uint64_t i_saddr = get_inode_address (i_num); ////

  // get start address of file
  std::vector<uint64_t> t_free_block_list;
  ret = get_free_data_blocks (g_my_dev->lba_size_bytes, t_free_block_list);

  // change addr to dnum
  std::vector<uint64_t> dnums_list;
  uint64_t t_dnum;
  for (int i = 0; i < t_free_block_list.size(); i++) {
    t_dnum = get_dnum_from_addr(t_free_block_list[i]);
    dnums_list.push_back (t_dnum);
  }
  
  update_data_bitmap (dnums_list, true); // set dnum true in dbitmap

  ret = init_dlb_data_block (t_free_block_list[0]); // does init and writing

  new_inode = init_inode (file_name, t_free_block_list[0], 1,
                          if_dir); // 1 lba size bytes for data link block

  // Write Inode to Inode region
  ret = write_inode (i_num, &new_inode);

  // Update Inode bitmap
  std::vector<uint64_t> inums;
  inums.push_back (i_num);
  update_inode_bitmap (inums, true);

  // dir entry added to pdir
  ret = update_pdir_data (path, i_num, if_dir, true);

  // update all dirs in the path filesize
  uint16_t delta = g_my_dev->lba_size_bytes; //// only one dlb
  update_path_isizes (path_contents, delta, 1);

  return ret;
}

/*
    delete_file()

    deletes a file

*/

int
s2fs_delete_file (std::string path)
{ // for now just dealing with files

  int ret = -ENOSYS;
  // Get file inode num
  std::vector<std::string> path_contents = // vector to store dir names
      path_to_vec (path);
  InodeResult ires = Get_file_inode (path);
  uint32_t inum = ires.inum;
  s2fs_inode inode = ires.inode;

  // uint16_t if_dir = inode.i_type; // dir(=1) or file(=0)

  // Parent directory data updation
  ret = update_pdir_data (path, inum, 0, true); // file(=0)

  // Inode removal
  std::vector<uint64_t> inums;
  inums.push_back (inum);
  update_inode_bitmap (inums, false);

  // Data removal
  std::vector<uint64_t> inode_db_addr_list;
  get_data_block_addrs (inode.start_addr, inode_db_addr_list, true, 0, 0,
                        inode_db_addr_list.size () * g_my_dev->lba_size_bytes);

  std::vector<uint64_t> dnums_list;
  for (uint i = 0; i < inode_db_addr_list.size (); i++)
    {
      uint64_t dnum = (inode_db_addr_list[i] - fs_my_dev->data_address)
                      / g_my_dev->lba_size_bytes;

      dnums_list.push_back (dnum);
    }

  // call update_data_bitmap() -- here
  update_data_bitmap (dnums_list, false);

  // update all dirs in the path filesize
  uint16_t delta = inode.file_size; //// check??
  update_path_isizes (path_contents, delta, -1);

  return ret;
}

/*
    delete_dir()

    deletes a dir

*/
int
s2fs_delete_dir (std::string path)
{

  int ret = -ENOSYS;
  std::vector<std::string> path_contents
      = path_to_vec (path); // vector to store dir names
  // Get file inode num
  InodeResult ires = Get_file_inode (path);
  uint32_t inum = ires.inum;
  s2fs_inode inode = ires.inode;
  std::string dir_path;
  /* Dir reading */
  std::vector<Dir_entry> dir_data_rows;
  dir_data_rows.resize(inode.file_size/sizeof(Dir_entry));
  ret = read_data_from_dlb (inode.start_addr, dir_data_rows.data (),
                            inode.file_size, 0); // read_data_from_dlb

  // check if empty dir
  bool isEmpty;
  for (uint i = 0; i < dir_data_rows.size (); i++)
    {
      if (dir_data_rows[i].inum != 0)
        {
          isEmpty = false;
          break;
        }
    }

  if (!isEmpty)
    {
      // delete all dir entries
      for (uint i = 0; i < dir_data_rows.size (); i++)
        {

          if (dir_data_rows[i].entry_type == 1)
            { // is dir

              std::string child_dir_path
                  = path + "/" + dir_data_rows[i].entry_name;
              ret = s2fs_delete_dir (child_dir_path);
            }
          else if (inode.i_type == 0)
            { // is file

              std::string child_file_path
                  = path + "/" + dir_data_rows[i].entry_name;
              ret = s2fs_delete_file (child_file_path);
            }
        }
    }
  // delete the dir called for deletion
  ret = s2fs_delete_file (path);

  // update all dirs in the path filesize
  uint16_t delta = inode.file_size; //// check??
  update_path_isizes (path_contents, delta, -1);

  return ret;
}

/*
    if_file_exists()

    check if file exists, output in bool

    if_yes: true if file exists

*/
bool
s2fs_file_exists (std::string path)
{

  bool ret = false;
  std::vector<std::string> path_contents = // vector to store dir names
      path_to_vec (path);
  std::string file_name = path_contents.back (); // file name
  std::vector<Dir_entry> dir_data_rows;
  ret = read_pdir_data (path, dir_data_rows);

  for (uint i = 0; i < dir_data_rows.size (); i++)
    {
      if (dir_data_rows[i].entry_name == file_name)
        {
          ret = true;
          return ret;
        }
    }
  return ret;
}

/*
    move_file()

    Moves a file

    src_path: /path/to/source/file.txt

    dest_path: /path/to/destination/file.txt
*/
int
s2fs_move_file (std::string src_path, std::string dest_path)
{

  int ret = -ENOSYS;

  InodeResult src_ires = Get_file_inode (src_path);
  uint32_t src_inum = src_ires.inum;
  s2fs_inode src_inode = src_ires.inode;

  // Remove file at source
  // update pdir at src
  ret = update_pdir_data (src_path, src_inum, 0, false); // file(=0)

  if (ret != 0)
    {
      std::cerr << "Failed to move file, error at source" << std::endl;
    }

  // shift file to destination
  // update pdir at dest
  ret = update_pdir_data (dest_path, src_inum, 0, true); // file(=0)
  if (ret != 0)
    {
      std::cerr << "Failed to move file, error at destination" << std::endl;
    }

  return ret;
}

/*
    get_dir_children()

    Returns a list inums of children of a dir

*/
int
s2fs_get_dir_children (std::string path, std::vector<std::string> &inum_list)
{

  int ret = -ENOSYS;
  // Get dir inode num
  InodeResult ires = Get_file_inode (path);
  s2fs_inode inode = ires.inode;

  /* Dir reading */
  std::vector<Dir_entry> dir_data_rows;
  dir_data_rows.resize(inode.file_size/sizeof(Dir_entry));
  ret = read_data_from_dlb (inode.start_addr, dir_data_rows.data (),
                            inode.file_size, 0); // read_data_from_dlb

  for (uint i = 0; i < dir_data_rows.size (); i++)
    {
      if (dir_data_rows[i].inum != 0)
        {
          inum_list.push_back (dir_data_rows[i].entry_name);
        }
    }
  return ret;
}
