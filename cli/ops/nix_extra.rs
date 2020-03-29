// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
// These are functions that should/will be in the nix crate, but aren't yet in nix 0.17

use nix::errno::Errno;
use nix::fcntl::AtFlags;
use nix::unistd::AccessFlags;
use nix::{NixPath, Result};
use std::os::unix::io::RawFd;

use libc::{gid_t, uid_t};
use nix::unistd::{Gid, Uid};

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
  // let (uid, gid) = chown_raw_ids(owner, group);

  // According to the POSIX specification, -1 is used to indicate that owner and group
  // are not to be changed.  Since uid_t and gid_t are unsigned types, we have to wrap
  // around to get -1.
  let uid: libc::uid_t = owner
    .map(Into::into)
    .unwrap_or_else(|| (0 as uid_t).wrapping_sub(1));
  let gid: libc::gid_t = group
    .map(Into::into)
    .unwrap_or_else(|| (0 as gid_t).wrapping_sub(1));

  let res = unsafe { libc::fchown(fd, uid, gid) };

  Errno::result(res).map(drop)
}

//////////////////////

use std::path::Path;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
#[allow(unused_imports)]
use std::ptr;
use std::mem;
use libc::c_int;

// #[allow(dead_code)]
fn cstr(path: &Path) -> std::io::Result<CString> {
    Ok(CString::new(path.as_os_str().as_bytes())?)
}

/// Based on https://github.com/rust-lang/rust/blob/master/src/libstd/sys/unix/weak.rs
#[cfg(target_os = "linux")]
// #[allow(unused_imports)]
macro_rules! syscall {
    (fn $name:ident($sysname:ident, $($arg_name:ident: $t:ty),*) -> $ret:ty) => (
        unsafe fn $name($($arg_name:$t),*) -> $ret {
            use libc::*;
            syscall(
                // concat_idents only accepts idents (not paths).
                // concat_idents!(SYS_, $name),
                $sysname,
                $($arg_name as c_long),*
            ) as $ret
        }
    )
}

/// Based on https://github.com/rust-lang/rust/blob/master/src/libstd/sys/unix/fs.rs

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

fn cvt<T: IsMinusOne>(t: T) -> std::io::Result<T> {
    if t.is_minus_one() { Err(std::io::Error::last_os_error()) } else { Ok(t) }
}

// `statx` not exposed on musl and other libcs, see https://github.com/rust-lang/rust/pull/67774
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


// `c_ulong` on gnu-mips, `dev_t` otherwise
use libc::dev_t;

// `i64` on gnu-x86_64-x32, `c_ulong`/`c_long` otherwise.
type ntime_t = i64;

#[allow(unused)]
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
  stat: libc::stat64; // nix::sys::stat::FileStat = libc::stat, which seems to be only nominally different
  st_btime: libc::time_t,
  st_btime_nsec: ntime_t,
}

// #[cfg(all(target_os = "linux", target_env = "gnu"))]
cfg_has_statx! {{
  /*
  #[derive(Clone)]
  pub struct FileAttr {
    stat: libc::stat64,
    statx_extra_fields: Option<StatxExtraFields>,
  }

  #[derive(Clone)]
  struct StatxExtraFields {
    // This is needed to check if btime is supported by the filesystem.
    stx_mask: u32,
    stx_btime: libc::statx_timestamp,
  }
  */

  // We prefer `statx` on Linux if available, which contains file creation time.
  // Default `stat64` contains no creation time.
  //#[allow(dead_code)]
  unsafe fn try_statx(
    fd: c_int,
    path: *const libc::c_char,
    flags: i32,
    mask: u32,
  ) -> Option<std::io::Result<ExtraStat>> {
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
            fd: c_int,
            pathname: *const libc::c_char,
            flags: c_int,
            mask: libc::c_uint,
            statxbuf: *mut libc::statx
        ) -> c_int
    }

    match STATX_STATE.load(Ordering::Relaxed) {
      0 => {
        // It is a trick to call `statx` with NULL pointers to check if the syscall
        // is available. According to the manual, it is expected to fail with EFAULT.
        // We do this mainly for performance, since it is nearly hundreds times
        // faster than a normal successful call.
        let err = cvt(statx(0, ptr::null(), 0, libc::STATX_ALL, ptr::null_mut()))
          .err() // Result<T, E> -> Option<E>
          .and_then(|e| e.raw_os_error());
        // We don't check `err == Some(libc::ENOSYS)` because the syscall may be limited
        // and returns `EPERM`. Listing all possible errors seems not a good idea.
        // See: https://github.com/rust-lang/rust/issues/65662
        if err != Some(libc::EFAULT) {
          STATX_STATE.store(1, Ordering::Relaxed);
          return None;
        }
        STATX_STATE.store(2, Ordering::Relaxed);
      }
      1 => return None,
      _ => {}
    }

    let mut buf: libc::statx = mem::zeroed();
    if let Err(err) = cvt(statx(fd, path, flags, mask, &mut buf)) {
      return Some(Err(err));
    }

    // TODO(jp)
    // We cannot fill `stat64` exhaustively because of private padding fields.
    let mut stat: libc::stat64 = mem::zeroed();
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
    Some(Ok(ExtraStat { stat, st_btime = buf.stx_btime.tv_sec as libc::time_t, st_btime_nsec = buf.stx_btime.tv_nsec as ntime_t }))

  }
} /* else {
  #[derive(Clone)]
  pub struct FileAttr {
    stat: libc::stat64,
  }
}} */

cfg_has_statx! {{
  impl ExtraStat {
    fn from_stat64(stat: libc::stat64) -> Self {
      Self { stat, st_btime = 0, st_btime_nsec = 0 }
    }
  }
} else {
  #[cfg(target_os = "netbsd")]
  impl ExtraStat {
    fn from_stat64(stat: libc::stat64) -> Self {
      Self { stat, st_btime = stat.st_birthtime, st_btime_nsec = stat.st_birthtimensec }
    }
  }
  #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos"))]
  impl ExtraStat {
    fn from_stat64(stat: libc::stat64) -> Self {
      Self { stat, st_btime = stat.st_birthtime, st_btime_nsec = stat.st_birthtime_nsec }
    }
  }
  #[cfg(not(any(target_os = "netbsd", target_os = "freebsd", target_os = "openbsd", target_os = "macos")))]
  impl ExtraStat {
    fn from_stat64(stat: libc::stat64) -> Self {
      Self { stat, st_btime = 0, st_btime_nsec = 0 }
    }
  }
}}

/*
cfg_has_statx! {{
  impl FileAttr {
    fn from_stat64(stat: libc::stat64) -> Self {
      Self { stat, statx_extra_fields: None }
    }
  }
} else {
  impl FileAttr {
      fn from_stat64(stat: libc::stat64) -> Self {
          Self { stat }
      }
  }
}}
*/

// #[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(dead_code)]
pub fn fstatat<P: ?Sized + NixPath>(dirfd: Option<RawFd>, path: &P, nofollow: bool) -> std::io::Result<ExtraStat> {
// pub fn my_fstatat(dirfd: Option<RawFd>, path: &Path, nofollow: bool) -> std::io::Result<ExtraStat> {
  let p = cstr(path)?;
  let flag = if nofollow {
    libc::AT_SYMLINK_NOFOLLOW
  } else {
    0
  };
  let fd = dirfd.unwrap_or(libc::AT_FDCWD);

  cfg_has_statx! {
    if let Some(ret) = unsafe { try_statx(
      fd,
      p.as_ptr(),
      flag | libc::AT_STATX_SYNC_AS_STAT,
      libc::STATX_ALL,
    ) } {
      return ret;
    }
  }

  let mut stat: libc::stat64 = unsafe { mem::zeroed() };
  cvt(unsafe { libc::fstatat64(fd, p.as_ptr(), &mut stat, flag) })?;
  Ok(ExtraAttr::from_stat64(stat))
}

#[allow(dead_code)]
pub fn fstat(fd: RawFd) -> std::io::Result<ExtraStat> {
  let p = cstr(Path::new(""))?;

  cfg_has_statx! {
    if let Some(ret) = unsafe { try_statx(
      fd,
      p.as_ptr(),
      libc::AT_STATX_SYNC_AS_STAT | libc::AT_EMPTY_PATH,
      libc::STATX_ALL,
    ) } {
      return ret;
    }
  }

  let mut stat: libc::stat64 = unsafe { mem::zeroed() };
  cvt(unsafe { libc::fstat64(fd, &mut stat) })?;
  Ok(ExtraAttr::from_stat64(stat))
}




#[cfg(test)]
mod tests {
  use super::*;
  use nix::fcntl::{open, OFlag};
  use nix::sys::stat::Mode;
  use nix::unistd::AccessFlags;
  use std::fs::File;

  #[test]
  fn test_faccessat_none_not_existing() {
    use nix::fcntl::AtFlags;
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
    use nix::fcntl::AtFlags;
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
    use nix::fcntl::AtFlags;
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
    use nix::fcntl::AtFlags;
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
    // let _dr = ::DirRestore::new();
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
