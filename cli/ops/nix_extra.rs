// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
// These are functions that should/will be in the nix crate, but aren't yet in nix 0.17

use nix::errno::Errno;
use nix::fcntl::AtFlags;
use nix::unistd::AccessFlags;
use nix::{NixPath, Result};
use std::os::unix::io::RawFd;

use libc::{gid_t, uid_t};
use nix::unistd::{Gid, Uid};

/*
/// Computes the raw fd consumed by a function of the form `*at`.
fn at_rawfd(fd: Option<RawFd>) -> std::os::raw::c_int {
    match fd {
        None => libc::AT_FDCWD,
        Some(fd) => fd,
    }
}
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

/*
/// Computes the raw UID and GID values to pass to a `*chown` call.
fn chown_raw_ids(owner: Option<Uid>, group: Option<Gid>) -> (libc::uid_t, libc::gid_t) {
    // According to the POSIX specification, -1 is used to indicate that owner and group
    // are not to be changed.  Since uid_t and gid_t are unsigned types, we have to wrap
    // around to get -1.
    let uid = owner.map(Into::into)
        .unwrap_or_else(|| (0 as uid_t).wrapping_sub(1));
    let gid = group.map(Into::into)
        .unwrap_or_else(|| (0 as gid_t).wrapping_sub(1));
    (uid, gid)
}
*/

/// Change the ownership of the file specified by a file descriptor to be owned
/// by the specified `owner` (user) and `group` (see
/// [fchown(2)](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fchown.html).
///
/// The owner/group for the provided path name will not be modified if `None` is
/// provided for that argument.  Ownership change will be attempted for the fd
/// only if `Some` owner/group is provided.
#[allow(dead_code)]
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
