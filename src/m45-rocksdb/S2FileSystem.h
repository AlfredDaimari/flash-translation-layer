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

#ifndef STOSYS_PROJECT_S2FILESYSTEM_H
#define STOSYS_PROJECT_S2FILESYSTEM_H

#include "rocksdb/env.h"
#include "rocksdb/file_system.h"
#include "rocksdb/io_status.h"
#include "rocksdb/status.h"

#include <cstdint>
#include <iostream>
#include <sys/types.h>
#include <zns_device.h>

namespace ROCKSDB_NAMESPACE
{
class S2SequentialFile : public FSSequentialFile
{
public:
  S2SequentialFile (std::string path);
  virtual ~S2SequentialFile ();
  IOStatus Read (size_t n, const IOOptions &options, Slice *result,
                 char *scratch, IODebugContext *dbg) override;

  IOStatus Skip (uint64_t n) override;

private:
  uint64_t fd;
};

class S2WritableFile : public FSWritableFile
{
public:
  S2WritableFile (std::string path);

  virtual ~S2WritableFile ();

  IOStatus Append (const Slice &data, const IOOptions &options,
                   IODebugContext *dbg) override;

  IOStatus Close (const IOOptions &options, IODebugContext *dbg) override;

  IOStatus Flush (const IOOptions &options, IODebugContext *dbg) override;
  IOStatus Sync (const IOOptions &options, IODebugContext *dbg) override;

private:
  uint64_t fd;
};

class S2RandomAccessFile : public FSRandomAccessFile
{
public:
  S2RandomAccessFile (std::string path);

  virtual ~S2RandomAccessFile ();

  IOStatus Read (uint64_t offset, size_t n, const IOOptions &options,
                 Slice *result, char *scratch,
                 IODebugContext *dbg) const override;

private:
  uint64_t fd;
};

class S2Logger : public Logger
{
public:
  S2Logger ();
  virtual ~S2Logger ();

private:
  uint64_t fd;
};

class S2FSDirectory : public FSDirectory
{
public:
  S2FSDirectory ();
  virtual ~S2FSDirectory ();
  IOStatus Fsync (const IOOptions &options, IODebugContext *dbg) override;
};
}

namespace ROCKSDB_NAMESPACE
{

class S2FileSystem : public FileSystem
{
public:
  // No copying allowed
  S2FileSystem (std::string uri, bool debug);
  S2FileSystem (const S2FileSystem &) = delete;
  virtual ~S2FileSystem ();

  IOStatus IsDirectory (const std::string &, const IOOptions &options,
                        bool *is_dir, IODebugContext *) override;

  IOStatus NewSequentialFile (const std::string &fname,
                              const FileOptions &file_opts,
                              std::unique_ptr<FSSequentialFile> *result,
                              __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus NewRandomAccessFile (const std::string &fname,
                                const FileOptions &file_opts,
                                std::unique_ptr<FSRandomAccessFile> *result,
                                __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus NewWritableFile (const std::string &fname,
                            const FileOptions &file_opts,
                            std::unique_ptr<FSWritableFile> *result,
                            __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus ReopenWritableFile (const std::string &, const FileOptions &,
                               std::unique_ptr<FSWritableFile> *,
                               IODebugContext *);

  IOStatus NewRandomRWFile (const std::string &, const FileOptions &,
                            std::unique_ptr<FSRandomRWFile> *,
                            IODebugContext *);

  IOStatus
  NewMemoryMappedFileBuffer (const std::string &,
                             std::unique_ptr<MemoryMappedFileBuffer> *);

  IOStatus NewDirectory (const std::string &name, const IOOptions &io_opts,
                         std::unique_ptr<FSDirectory> *result,
                         __attribute__ ((unused)) IODebugContext *dbg);

  const char *Name () const;

  IOStatus GetFreeSpace (const std::string &, const IOOptions &, uint64_t *,
                         IODebugContext *);

  IOStatus Truncate (const std::string &, size_t, const IOOptions &,
                     IODebugContext *);

  IOStatus CreateDir (const std::string &dirname, const IOOptions &options,
                      __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus CreateDirIfMissing (const std::string &dirname,
                               const IOOptions &options,
                               __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus GetFileSize (const std::string &fname, const IOOptions &options,
                        uint64_t *file_size,
                        __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus DeleteDir (const std::string &dirname, const IOOptions &options,
                      __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus GetFileModificationTime (const std::string &fname,
                                    const IOOptions &options,
                                    uint64_t *file_mtime,
                                    __attribute__ ((unused))
                                    IODebugContext *dbg);

  IOStatus GetAbsolutePath (const std::string &db_path,
                            const IOOptions &options, std::string *output_path,
                            __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus DeleteFile (const std::string &fname, const IOOptions &options,
                       IODebugContext *dbg);

  IOStatus NewLogger (const std::string &fname, const IOOptions &io_opts,
                      std::shared_ptr<Logger> *result,
                      __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus GetTestDirectory (const IOOptions &options, std::string *path,
                             __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus UnlockFile (FileLock *lock, const IOOptions &options,
                       __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus LockFile (const std::string &fname, const IOOptions &options,
                     FileLock **lock,
                     __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus AreFilesSame (const std::string &, const std::string &,
                         const IOOptions &, bool *, IODebugContext *);

  IOStatus NumFileLinks (const std::string &, const IOOptions &, uint64_t *,
                         IODebugContext *);

  IOStatus LinkFile (const std::string &, const std::string &,
                     const IOOptions &, IODebugContext *);

  IOStatus RenameFile (const std::string &src, const std::string &target,
                       const IOOptions &options,
                       __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus GetChildrenFileAttributes (const std::string &dir,
                                      const IOOptions &options,
                                      std::vector<FileAttributes> *result,
                                      __attribute__ ((unused))
                                      IODebugContext *dbg);

  IOStatus GetChildren (const std::string &dir, const IOOptions &options,
                        std::vector<std::string> *result,
                        __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus FileExists (const std::string &fname, const IOOptions &options,
                       __attribute__ ((unused)) IODebugContext *dbg);

  IOStatus ReuseWritableFile (const std::string &fname,
                              const std::string &old_fname,
                              const FileOptions &file_opts,
                              std::unique_ptr<FSWritableFile> *result,
                              __attribute__ ((unused)) IODebugContext *dbg);

private:
  struct user_zns_device *_zns_dev;
  std::string _uri;
  const std::string _fs_delimiter = "/";
};
}

// structs to implement posix calls

// each lba of size 4096 bytes will be able to hold 16 inodes
struct s2fs_inode
{
  uint64_t i_type;     // file or directory    ~8 bytes
  uint64_t blocks;     // size of file = blocks_size - (size_m) ~16 bytes
  uint64_t file_size;  // ~ 24 bytes (this size doesn't include block size)
  uint64_t start_addr; // ~ 32 bytes
  uint64_t i_mtime;    // modified time    ~ 40 bytes
  uint64_t i_ctime;    // created time     ~ 48 bytes
  char file_name[208]; // name of file ~ 256 bytes
};

// Helper struct for Get_file_inode function (rem)
struct InodeResult
{
  s2fs_inode inode;
  uint32_t inum;
};

// Dir entry struct (row) ~
struct Dir_entry
{

  uint64_t inum;        // inode number
  uint64_t entry_type;  // file or directory(0)
  char entry_name[208]; // name of file/dir 256
  char padding[32];
};

// size of each row ~ 128 bits, 16 bytes
// Total number of rows for each block will be 4096/16 = 256
struct data_lnb_row
{
  uint64_t address;
  uint64_t size; // max ~ 4096 bytes
};

struct fd_info
{
  std::string file_name;
  uint32_t fd_id;
  uint32_t inode_id;
  uint64_t inode_address;
  mode_t mode; // check for append
};

// struct with fs info
struct fs_zns_device
{
  uint64_t inode_bitmap_address;
  uint64_t inode_bitmap_size; // byte size with lba padding
  uint64_t total_inodes;
  uint64_t data_bitmap_address;
  uint64_t data_bitmap_size; // byte size with lba padding
  uint64_t total_data_blocks;
  uint64_t inode_table_address;
  uint64_t data_address;
  uint32_t dlb_rows;  // number of rows in a data link block
  uint32_t dirb_rows; // number of rows in a directory block
};

int s2fs_init (struct user_zns_device *g_my_dev);

int s2fs_deinit ();

int s2fs_open (std::string filename, int oflag, mode_t mode);

int s2fs_close (int fd);

int s2fs_write (int fd, void *buf, size_t size, uint64_t offset);

int s2fs_read (int fd, void *buf, size_t size, uint64_t offset);

int s2fs_delete_file (std::string path);

int s2fs_delete_dir (std::string path);

int s2fs_move_file (std::string src_path, std::string dest_path);

bool s2fs_file_exists (std::string path);

int s2fs_create_file (std::string path, uint16_t if_dir);

int s2fs_get_dir_children (std::string, std::vector<std::string> &inum_list);

#endif // STOSYS_PROJECT_S2FILESYSTEM_H
