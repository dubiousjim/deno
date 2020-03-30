// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
// These are functions that should/will be in the nix crate, but aren't yet in nix 0.17

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag};
use nix::unistd::{AccessFlags, Gid, Uid};
use nix::{NixPath, Result};
use std::path::Path;
use std::ffi::{CString, CStr};
use std::mem;
use std::os::unix::io::RawFd;
#[allow(unused_imports)]
use std::ptr;

pub use nix::sys::stat::{mode_t, FileStat, Mode, SFlag};

// `c_ulong` on gnu-mips, `dev_t` otherwise
#[allow(unused_imports)]
pub use libc::dev_t;
// `i64` on gnu-x86_64-x32, `c_ulong`/`c_long` otherwise.
#[allow(non_camel_case_types)]
pub type ntime_t = i64;

#[cfg(any(target_os = "linux", target_os = "emscripten"))]
use libc::{fstat64, fstatat64, stat64};

#[cfg(not(any(
  target_os = "linux",
  target_os = "emscripten",
  target_os = "l4re"
)))]
use libc::{fstat as fstat64, fstatat as fstatat64, stat as stat64};

/*
#[cfg(target_os = "l4re")]
use libc::{fstat64};
#[cfg(any(target_os = "linux", target_os = "emscripten", target_os = "l4re"))]
use libc::{
    lstat64, dirent64, lseek64, open64, ftruncate64, off64_t, readdir64_r,
};
#[cfg(target_os = "android")]
use libc::{
    lstat as lstat64, dirent as dirent64, lseek64, open as open64,
    // missing: ftruncate, off_t
};
#[cfg(not(any(target_os = "linux", target_os = "emscripten", target_os = "l4re", target_os = "android")))]
use libc::{
    lstat as lstat64, dirent as dirent64, lseek as lseek64, open as open64, ftruncate as ftruncate64, off_t as off64_t,
};
#[cfg(not(any(target_os = "linux", target_os = "emscripten", target_os = "l4re", target_os = "solaris", target_os = "fuchsia", target_os = "redox")))]
use libc::readdir_r as readdir64_r;
*/

/// Based on https://github.com/nix-rust/nix/pull/1134
///
/// Checks the file named by `path` for accessibility according to the flags given by `mode`
///
/// If `dirfd` has a value, then `path` is relative to directory associated with the file descriptor.
///
/// If `dirfd` is `None`, then `path` is relative to the current working directory.
///
/// # References
///
/// [faccessat(2)](http://pubs.opengroup.org/onlinepubs/9699919799/functions/faccessat.html)
#[allow(dead_code)]
pub fn faccessat<P: ?Sized + NixPath>(
  dirfd: Option<RawFd>,
  path: &P,
  mode: AccessFlags,
  flag: AtFlags,
) -> Result<()> {
  let rawfd = match dirfd {
    None => libc::AT_FDCWD,
    Some(fd) => fd,
  };
  let res = path.with_nix_path(|cstr| unsafe {
    libc::faccessat(rawfd, cstr.as_ptr(), mode.bits(), flag.bits())
  })?;
  Errno::result(res).map(drop)
}

/// Change the ownership of the file specified by a file descriptor to be owned
/// by the specified `owner` (user) and `group` (see
/// [fchown(2)](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fchown.html).
///
/// The owner/group for the provided path name will not be modified if `None` is
/// provided for that argument.  Ownership change will be attempted for the fd
/// only if `Some` owner/group is provided.
pub fn fchown(fd: RawFd, owner: Option<Uid>, group: Option<Gid>) -> Result<()> {
  // According to the POSIX specification, -1 is used to indicate that owner and group
  // are not to be changed.  Since uid_t and gid_t are unsigned types, we have to wrap
  // around to get -1.
  let uid: libc::uid_t = owner
    .map(Into::into)
    .unwrap_or_else(|| (0 as libc::uid_t).wrapping_sub(1));
  let gid: libc::gid_t = group
    .map(Into::into)
    .unwrap_or_else(|| (0 as libc::gid_t).wrapping_sub(1));

  let res = unsafe { libc::fchown(fd, uid, gid) };
  Errno::result(res).map(drop)
}

/// Based on https://github.com/rust-lang/rust/blob/master/src/libstd/sys/unix/weak.rs
#[cfg(all(target_os = "linux", target_env = "gnu"))]
macro_rules! syscall {
  (fn $name:ident($sysname:ident, $($arg_name:ident: $t:ty),*) -> $ret:ty) => (
    unsafe fn $name($($arg_name:$t),*) -> $ret {
      use libc::*;
      syscall(
        /* concat_idents!(SYS_, $name) */ $sysname,
        $($arg_name as c_long),*
      ) as $ret
    }
  )
}

/// Based on https://github.com/rust-lang/rust/blob/master/src/libstd/sys/unix/fs.rs
/*
fn cstr(path: &Path) -> std::io::Result<CString> {
    Ok(CString::new(path.as_os_str().as_bytes())?)
}

trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i32 } // i8 i16 i64 isize

// same as nix::Errno::result(t), except for Err type
fn cvt<T: IsMinusOne>(t: T) -> std::io::Result<T> {
  if t.is_minus_one() { Err(std::io::Error::last_os_error()) } else { Ok(t) }
}

// Nix pattern is
// -> Result<()> {
  let res = path.with_nix_path(|cstr| {
    unsafe {
      libc::blah(cstr.as_ptr(), ...) // -> -1
    }
  })?;
  Errno::result(res).map(drop) // drop: N -> ()
}

Errno::last() -> Self
Errno::from_i32(i32) -> Self
Errno::desc(self) -> &str
unsafe Errno::clear()
Errno::result<N>(value: N) -> Result<N, nix::Error> // only use when -1 is the sentinel
// where N is isize, i32, i64, *mut c_void, sighandler_t

   if value == N::sentinel() {
     Err(nix::Error::Sys(Self::last()))
   } else {
     Ok(value)
   }

Nix enum Error {
  Sys(nix::errno::Errno),
  InvalidPath,
  InvalidUtf8,
  UnsupportedOperation
}
Error::last() -> new Sys(current Errno)
Error::invalid_argument() -> new Sys(EINVAL)
Error::from_errno(Errno) -> new Sys(Errno)
Error::as_errno(self) -> Option<Errno>
*/

// `statx` not exposed on musl and other libcs
// see https://github.com/rust-lang/rust/pull/67774
macro_rules! cfg_has_statx {
  ({ $($then_tt:tt)* } else { $($else_tt:tt)* }) => {
     cfg_if::cfg_if! {
       if #[cfg(all(target_os = "linux", target_env = "gnu"))] {
         $($then_tt)*
       } else {
         $($else_tt)*
       }
     }
  };
  ($($block_inner:tt)*) => {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
         $($block_inner)*
    }
  };
}

#[derive(Clone)]
pub struct ExtraStat {
  /*
    st_dev: dev_t,
    st_ino: libc::ino64_t,
    st_nlink: libc::nlink_t,
    st_mode: libc::mode_t,
    st_uid: libc::uid_t,
    st_gid: libc::gid_t,
    st_rdev: dev_t,
    st_size: libc::off64_t,
    st_blksize: libc::blksize_t,
    st_blocks: libc::blkcnt64_t,
    st_atime: libc::time_t,
    st_atime_nsec: ntime_t,
    st_mtime: libc::time_t,
    st_mtime_nsec: ntime_t,
    st_ctime: libc::time_t,
    st_ctime_nsec: ntime_t,
  */
  pub stat: stat64, // nix::sys::stat::FileStat = libc::stat/stat64
  pub st_btime: libc::time_t,
  pub st_btime_nsec: ntime_t,
}

cfg_has_statx! {{
  // We prefer `statx` on Linux if available, which contains file creation time.
  // Default `stat64` contains no creation time.
  unsafe fn try_statx(
    fd: libc::c_int,
    path: *const libc::c_char,
    flags: i32,
    mask: u32,
  ) -> Option<Result<ExtraStat>> {
    use std::sync::atomic::{AtomicU8, Ordering};

    // Linux kernel prior to 4.11 or glibc prior to glibc 2.28 don't support `statx`
    // We store the availability in global to avoid unnecessary syscalls.
    // 0: Unknown
    // 1: Not available
    // 2: Available
    static STATX_STATE: AtomicU8 = AtomicU8::new(0);
    syscall! {
        fn statx(
            SYS_statx,
            fd: libc::c_int,
            pathname: *const libc::c_char,
            flags: libc::c_int,
            mask: libc::c_uint,
            statxbuf: *mut libc::statx
        ) -> libc::c_int
    }

    match STATX_STATE.load(Ordering::Relaxed) {
      0 => {
        // It is a trick to call `statx` with NULL pointers to check if the syscall
        // is available. According to the manual, it is expected to fail with EFAULT.
        // We do this mainly for performance, since it is nearly hundreds times
        // faster than a normal successful call.
        let res = statx(0, ptr::null(), 0, libc::STATX_ALL, ptr::null_mut());
        /*
        let err = Errno::result(res)
          .err() // Result<T, E> -> Option<E>
          .and_then(|e| e.as_errno());
        */
        let err = if res == -1 {
          Some(Errno::last())
        } else {
          None
        };
        // We don't check `err == Some(ENOSYS)` because the syscall may be limited
        // and returns `EPERM`. Listing all possible errors seems not a good idea.
        // See: https://github.com/rust-lang/rust/issues/65662
        if err != Some(Errno::EFAULT) {
          STATX_STATE.store(1, Ordering::Relaxed);
          return None;
        }
        STATX_STATE.store(2, Ordering::Relaxed);
      }
      1 => return None,
      _ => {}
    }

    let mut buf: libc::statx = mem::zeroed();
    let res = statx(fd, path, flags, mask, &mut buf);
    /*
    if let Err(err) = Errno::result(res) { return Some(Err(err)); }
    */
    if res == -1 {
      return Some(Err(nix::Error::last()));
    }

    // We cannot fill `stat64` exhaustively because of private padding fields.
    let mut stat: stat64 = mem::zeroed();
    stat.st_dev = libc::makedev(buf.stx_dev_major, buf.stx_dev_minor) as dev_t;
    stat.st_ino = buf.stx_ino as libc::ino64_t;
    stat.st_nlink = buf.stx_nlink as libc::nlink_t;
    stat.st_mode = buf.stx_mode as libc::mode_t;
    stat.st_uid = buf.stx_uid as libc::uid_t;
    stat.st_gid = buf.stx_gid as libc::gid_t;
    stat.st_rdev = libc::makedev(buf.stx_rdev_major, buf.stx_rdev_minor) as dev_t;
    stat.st_size = buf.stx_size as libc::off64_t;
    stat.st_blksize = buf.stx_blksize as libc::blksize_t;
    stat.st_blocks = buf.stx_blocks as libc::blkcnt64_t;
    stat.st_atime = buf.stx_atime.tv_sec as libc::time_t;
    stat.st_atime_nsec = buf.stx_atime.tv_nsec as ntime_t;
    stat.st_mtime = buf.stx_mtime.tv_sec as libc::time_t;
    stat.st_mtime_nsec = buf.stx_mtime.tv_nsec as ntime_t;
    stat.st_ctime = buf.stx_ctime.tv_sec as libc::time_t;
    stat.st_ctime_nsec = buf.stx_ctime.tv_nsec as ntime_t;
    Some(Ok(ExtraStat { stat, st_btime: buf.stx_btime.tv_sec as libc::time_t, st_btime_nsec: buf.stx_btime.tv_nsec as ntime_t }))
  }

  impl ExtraStat {
    fn from_stat64(stat: stat64) -> Self {
      Self { stat, st_btime: 0, st_btime_nsec: 0 }
    }
  }

} else {
  impl ExtraStat {
    #[cfg(target_os = "netbsd")]
    fn from_stat64(stat: stat64) -> Self {
      Self { stat, st_btime: stat.st_birthtime, st_btime_nsec: stat.st_birthtimensec }
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
    fn from_stat64(stat: stat64) -> Self {
      Self { stat, st_btime: stat.st_birthtime, st_btime_nsec: stat.st_birthtime_nsec }
    }
    #[cfg(not(any(target_os = "netbsd", target_os = "freebsd", target_os = "openbsd", target_os = "macos")))]
    fn from_stat64(stat: stat64) -> Self {
      Self { stat, st_btime: 0, st_btime_nsec: 0 }
    }
  }
}}

#[allow(dead_code)]
pub fn fstatat<P: ?Sized + NixPath>(
  dirfd: Option<RawFd>,
  path: &P,
  nofollow: bool,
) -> Result<ExtraStat> {
  path
    .with_nix_path(|cstr| {
      let flag = if nofollow {
        libc::AT_SYMLINK_NOFOLLOW
      } else {
        0
      };
      let fd = dirfd.unwrap_or(libc::AT_FDCWD);

      cfg_has_statx! {
        if let Some(ret) = unsafe { try_statx(
          fd,
          cstr.as_ptr(),
          flag | libc::AT_STATX_SYNC_AS_STAT,
          libc::STATX_ALL,
        ) } {
          return ret;
        }
      }

      let mut stat: stat64 = unsafe { mem::zeroed() };
      let res = unsafe { fstatat64(fd, cstr.as_ptr(), &mut stat, flag) };
      Errno::result(res)?;
      Ok(ExtraStat::from_stat64(stat))
    })
    .and_then(|ok| ok)
}

#[allow(dead_code)]
pub fn fstat(fd: RawFd) -> Result<ExtraStat> {
  cfg_has_statx! {
    let p = CString::new("").unwrap();
    if let Some(ret) = unsafe { try_statx(
      fd,
      p.as_ptr(),
      libc::AT_STATX_SYNC_AS_STAT | libc::AT_EMPTY_PATH,
      libc::STATX_ALL,
    ) } {
      return ret;
    }
  }

  let mut stat: stat64 = unsafe { mem::zeroed() };
  let res = unsafe { fstat64(fd, &mut stat) };
  Errno::result(res)?;
  Ok(ExtraStat::from_stat64(stat))
}

fn cstr(path: &Path) -> Result<CString> {
  use std::os::unix::ffi::OsStrExt;
  match CString::new(path.as_os_str().as_bytes()) {
    Ok(cstr) => Ok(cstr),
    Err(_) => Err(nix::Error::InvalidUtf8),
  }
}

#[allow(dead_code)]
pub fn mkdirat<P: ?Sized + NixPath>(dirfd: Option<RawFd>, path: &P, mode: Mode, recursive: bool) -> Result<()> {
  path.with_nix_path(|cstr| {
    let path = match cstr.to_str() {
      Ok(s) => Path::new(s),
      Err(_) => return Err(nix::Error::InvalidUtf8),
    };
    match dirfd {
      Some(fd) => _mkdirat(fd, path.as_ref(), mode.bits() as mode_t, recursive),
      None => _mkdir(path.as_ref(), mode.bits() as mode_t, recursive),
    }
  })
  .and_then(|ok| ok)
}

fn _mkdirat(fd: RawFd, path: &Path, mode: mode_t, recursive: bool) -> Result<()> {
  if recursive {
    _mkdirat_all(fd, path, mode)
  } else {
    let cstr = cstr(path)?;
    let res = unsafe { libc::mkdirat(fd, cstr.as_ptr(), mode) };
    Errno::result(res).map(drop)
  }
}

fn _mkdirat_all(fd: RawFd, path: &Path, mode: mode_t) -> Result<()> {
  if path == Path::new("") {
    return Ok(());
  }
  match _mkdirat(fd, path, mode, false) {
    Ok(()) => return Ok(()),
    // Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
    // Err(ref e) if e == nix::Error::Sys(nix::errno::Errno::ENOENT) => {}
    Err(ref e) if e.as_errno() == Some(nix::errno::Errno::ENOENT) => {}
    Err(_) if path.is_dir() => return Ok(()),
    Err(e) => return Err(e),
  }
  match path.parent() {
    Some(p) => _mkdirat_all(fd, p, 0o777)?,
    // None => { return Err(std::io::Error::new(std::io::ErrorKind::Other, "failed to create whole tree")); }
    None => { return Err(nix::Error::Sys(nix::errno::Errno::EACCES)); },
  }
  match _mkdirat(fd, path, mode, false) {
    Ok(()) => Ok(()),
    Err(_) if path.is_dir() => Ok(()),
    Err(e) => Err(e),
  }
}

fn _mkdir(path: &Path, mode: mode_t, recursive: bool) -> Result<()> {
  if recursive {
    _mkdir_all(path, mode)
  } else {
    let cstr = cstr(path)?;
    let res = unsafe { libc::mkdir(cstr.as_ptr(), mode) };
    Errno::result(res).map(drop)
  }
}

fn _mkdir_all(path: &Path, mode: mode_t) -> Result<()> {
  if path == Path::new("") {
    return Ok(());
  }
  match _mkdir(path, mode, false) {
    Ok(()) => return Ok(()),
    // Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
    // Err(ref e) if e == nix::Error::Sys(nix::errno::Errno::ENOENT) => {}
    Err(ref e) if e.as_errno() == Some(nix::errno::Errno::ENOENT) => {}
    Err(_) if path.is_dir() => return Ok(()),
    Err(e) => return Err(e),
  }
  match path.parent() {
    Some(p) => _mkdir_all(p, 0o777)?,
    // None => { return Err(std::io::Error::new(std::io::ErrorKind::Other, "failed to create whole tree")); }
    None => { return Err(nix::Error::Sys(nix::errno::Errno::EACCES)); },
  }
  match _mkdir(path, mode, false) {
    Ok(()) => Ok(()),
    Err(_) if path.is_dir() => Ok(()),
    Err(e) => Err(e),
  }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum UnlinkatFlags {
  RemoveDirAll,
  RemoveDir,
  NoRemoveDir,
}

#[allow(dead_code)]
pub fn unlinkat<P: ?Sized + NixPath>(
  dirfd: Option<RawFd>,
  path: &P,
  flag: UnlinkatFlags,
) -> Result<()> {
  let fd = dirfd.unwrap_or(libc::AT_FDCWD);
  path.with_nix_path(|cstr| {
    let atflag = match flag {
      UnlinkatFlags::RemoveDirAll => {
        let mut stat: stat64 = unsafe { mem::zeroed() };
        let res = unsafe { fstatat64(fd, cstr.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
        Errno::result(res)?;
        let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        if is_dir {
          return _unlinkat_all(fd, cstr)
        } else {
          AtFlags::empty()
        }
      }
      UnlinkatFlags::RemoveDir => AtFlags::AT_REMOVEDIR,
      UnlinkatFlags::NoRemoveDir => AtFlags::empty(),
    };
    let res = unsafe {
      libc::unlinkat(fd, cstr.as_ptr(), atflag.bits() as libc::c_int)
    };
    Errno::result(res).map(drop)
  })
  .and_then(|ok| ok)
}

fn _unlinkat_all(fd: RawFd, path: &CStr) -> Result<()> {
  let mut dir = nix::dir::Dir::openat(fd, path, OFlag::O_RDONLY, Mode::empty())?;
  let curdir_name = CString::new(".").unwrap().as_c_str();
  let pardir_name = CString::new("..").unwrap().as_c_str();
  for child in dir.iter() {
    let child = child?;
    let child_name = child.file_name();
    if child_name != curdir_name && child_name != pardir_name {
      let is_dir = match child.file_type() {
        Some(nix::dir::Type::Directory) => true,
        Some(_) => false,
        None => {
          let mut stat: stat64 = unsafe { mem::zeroed() };
          let res = unsafe { fstatat64(fd, child_name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
          Errno::result(res)?;
          (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
        }
      };
      if is_dir {
        _unlinkat_all(fd, child_name)?;
      } else {
        let atflag = AtFlags::empty();
        let res = unsafe {
          libc::unlinkat(fd, child_name.as_ptr(), atflag.bits() as libc::c_int)
        };
        Errno::result(res)?;
      }
    }
  }
  let atflag = AtFlags::AT_REMOVEDIR;
  let res = unsafe {
    libc::unlinkat(fd, path.as_ptr(), atflag.bits() as libc::c_int)
  };
  Errno::result(res).map(drop)
}

#[cfg(test)]
mod tests {
  use super::*;
  use nix::fcntl::{open, AtFlags, OFlag};
  use nix::sys::stat::Mode;
  use nix::unistd::AccessFlags;
  use std::fs::File;

  #[test]
  fn test_faccessat_none_not_existing() {
    let tempdir = tempfile::tempdir().unwrap();
    let dir = tempdir.path().join("does_not_exist.txt");
    assert_eq!(
      faccessat(None, &dir, AccessFlags::F_OK, AtFlags::empty())
        .err()
        .unwrap()
        .as_errno()
        .unwrap(),
      Errno::ENOENT
    );
  }

  #[test]
  fn test_faccessat_not_existing() {
    let tempdir = tempfile::tempdir().unwrap();
    let dirfd = open(tempdir.path(), OFlag::empty(), Mode::empty()).unwrap();
    let not_exist_file = "does_not_exist.txt";
    assert_eq!(
      faccessat(
        Some(dirfd),
        not_exist_file,
        AccessFlags::F_OK,
        AtFlags::empty()
      )
      .err()
      .unwrap()
      .as_errno()
      .unwrap(),
      Errno::ENOENT
    );
  }

  #[test]
  fn test_faccessat_none_file_exists() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path().join("does_exist.txt");
    let _file = File::create(path.clone()).unwrap();
    assert!(faccessat(
      None,
      &path,
      AccessFlags::R_OK | AccessFlags::W_OK,
      AtFlags::empty()
    )
    .is_ok());
  }

  #[test]
  fn test_faccessat_file_exists() {
    let tempdir = tempfile::tempdir().unwrap();
    let dirfd = open(tempdir.path(), OFlag::empty(), Mode::empty()).unwrap();
    let exist_file = "does_exist.txt";
    let path = tempdir.path().join(exist_file);
    let _file = File::create(path.clone()).unwrap();
    assert!(faccessat(
      Some(dirfd),
      &path,
      AccessFlags::R_OK | AccessFlags::W_OK,
      AtFlags::empty()
    )
    .is_ok());
  }

  #[test]
  fn test_fchown() {
    use std::os::unix::io::AsRawFd;
    // Testing for anything other than our own UID/GID is hard.
    let uid = Some(nix::unistd::getuid());
    let gid = Some(nix::unistd::getgid());

    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path().join("file");
    let file = File::create(&path).unwrap();
    let fd = file.as_raw_fd();
    // let fd = open(&path, OFlag::empty(), Mode::empty()).unwrap();

    fchown(fd, uid, gid).unwrap();
    fchown(fd, uid, None).unwrap();
    fchown(fd, None, gid).unwrap();
    // std::fs::remove_file(&path).unwrap();
  }
}
