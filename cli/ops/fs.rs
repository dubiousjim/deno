// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
// Some deserializer fields are only used on Unix and Windows build fails without it
use super::dispatch_json::{blocking_json, Deserialize, JsonOp, Value};
use super::io::{FileMetadata, StreamResource};
use crate::fs::resolve_from_cwd;
use crate::op_error::OpError;
use crate::ops::dispatch_json::JsonResult;
use crate::state::State;
use deno_core::*;
use futures::future::FutureExt;
use std::convert::{From, TryInto};
use std::env;
use std::fs as std_fs;
use tokio::fs as tokio_fs;
use std::io; // io::{Result, Error, SeekFrom, copy} and io::ErrorKind (make_temp and windows chown)
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use rand::{thread_rng, Rng};
// use remove_dir_all::remove_dir_all;
use utime::set_file_times;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(unix)]
use nix::fcntl::{fcntl, FcntlArg, OFlag};

#[cfg(unix)]
fn get_mode(fd: RawFd) -> Result<OFlag, ErrBox> {
  let flags = fcntl(fd, FcntlArg::F_GETFL)?;
  let flags = OFlag::from_bits_truncate(flags);
  Ok(OFlag::O_ACCMODE & flags)
}

#[cfg(unix)]
pub fn my_check_open_for_writing(
  file: &tokio_fs::File,
) -> Result<RawFd, ErrBox> {
  let fd = file.as_raw_fd();
  let mode = get_mode(fd)?;
  if mode == OFlag::O_RDWR || mode == OFlag::O_WRONLY {
    Ok(fd)
  } else {
    let e = OpError::permission_denied(
      "run again with the --allow-write flag".to_string(),
    );
    Err(ErrBox::from(e))
  }
}

#[cfg(unix)]
pub fn my_check_open_for_reading(
  file: &tokio_fs::File,
) -> Result<RawFd, ErrBox> {
  let fd = file.as_raw_fd();
  let mode = get_mode(fd)?;
  if mode == OFlag::O_RDWR || mode == OFlag::O_RDONLY {
    Ok(fd)
  } else {
    let e = OpError::permission_denied(
      "run again with the --allow-read flag".to_string(),
    );
    Err(ErrBox::from(e))
  }
}


#[cfg(unix)]
fn set_dir_permissions(builder: &mut std_fs::DirBuilder, mode: u32) {
  use std::os::unix::fs::DirBuilderExt;
  let mode = mode & 0o777;
  debug!("set dir mode to {:o}", mode);
  builder.mode(mode);
}

#[cfg(not(unix))]
fn set_dir_permissions(_builder: &mut std_fs::DirBuilder, _mode: u32) {
  // NOOP on windows
}

pub fn init(i: &mut Isolate, s: &State) {
  i.register_op("op_open", s.stateful_json_op(op_open));
  i.register_op("op_seek", s.stateful_json_op(op_seek));
  i.register_op("op_sync", s.stateful_json_op(op_sync));
  i.register_op("op_datasync", s.stateful_json_op(op_datasync));
  i.register_op("op_umask", s.stateful_json_op(op_umask));
  i.register_op("op_chdir", s.stateful_json_op(op_chdir));
  i.register_op("op_mkdir", s.stateful_json_op(op_mkdir));
  i.register_op("op_chmod", s.stateful_json_op(op_chmod));
  i.register_op("op_chown", s.stateful_json_op(op_chown));
  i.register_op("op_remove", s.stateful_json_op(op_remove));
  i.register_op("op_copy_file", s.stateful_json_op(op_copy_file));
  i.register_op("op_stat", s.stateful_json_op(op_stat));
  i.register_op("op_realpath", s.stateful_json_op(op_realpath));
  i.register_op("op_read_dir", s.stateful_json_op(op_read_dir));
  i.register_op("op_rename", s.stateful_json_op(op_rename));
  i.register_op("op_link", s.stateful_json_op(op_link));
  i.register_op("op_symlink", s.stateful_json_op(op_symlink));
  i.register_op("op_read_link", s.stateful_json_op(op_read_link));
  i.register_op("op_truncate", s.stateful_json_op(op_truncate));
  i.register_op("op_make_temp_dir", s.stateful_json_op(op_make_temp_dir));
  i.register_op("op_make_temp_file", s.stateful_json_op(op_make_temp_file));
  i.register_op("op_cwd", s.stateful_json_op(op_cwd));
  i.register_op("op_utime", s.stateful_json_op(op_utime));
  i.register_op("op_ftruncate", s.stateful_json_op(op_ftruncate));
  i.register_op("op_fchmod", s.stateful_json_op(op_fchmod));
  i.register_op("op_futime", s.stateful_json_op(op_futime));
  i.register_op("op_fstat", s.stateful_json_op(op_fstat));
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenArgs {
  promise_id: Option<u64>,
  path: String,
  options: Option<OpenOptions>,
  open_mode: Option<String>,
  mode: Option<u32>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
struct OpenOptions {
  read: bool,
  write: bool,
  create: bool,
  truncate: bool,
  append: bool,
  create_new: bool,
}

fn op_open(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: OpenArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let state_ = state.clone();
  let gave_mode = args.mode.is_some();

  let mut open_options = if let Some(mode) = args.mode {
    #[allow(unused_mut)]
    let mut std_options = std_fs::OpenOptions::new();
    // mode only used if creating the file on Unix
    // if not specified, defaults to 0o666
    #[cfg(unix)]
    {
      use std::os::unix::fs::OpenOptionsExt;
      std_options.mode(mode & 0o777);
    }
    #[cfg(not(unix))]
    let _ = mode; // avoid unused warning
    tokio_fs::OpenOptions::from(std_options)
  } else {
    tokio_fs::OpenOptions::new()
  };

  if let Some(options) = args.options {
    if options.read {
      state.check_read(&path)?;
    }

    if options.write || options.append {
      state.check_write(&path)?;
    }

    if gave_mode && !(options.create || options.create_new) {
      return Err(OpError::type_error(
        "specified mode without allowing file creation".to_string(),
      ));
    }

    open_options
      .read(options.read)
      .create(options.create)
      .write(options.write)
      .truncate(options.truncate)
      .append(options.append)
      .create_new(options.create_new);
  } else if let Some(open_mode) = args.open_mode {
    let open_mode = open_mode.as_ref();
    match open_mode {
      "r" => {
        state.check_read(&path)?;
        if gave_mode {
          return Err(OpError::type_error(
            "specified mode for read-only open".to_string(),
          ));
        }
      }
      "w" | "a" | "x" => {
        state.check_write(&path)?;
      }
      &_ => {
        state.check_read(&path)?;
        state.check_write(&path)?;
      }
    };

    match open_mode {
      "r" => {
        open_options.read(true);
      }
      "r+" => {
        open_options.read(true).write(true);
      }
      "w" => {
        open_options.create(true).write(true).truncate(true);
      }
      "w+" => {
        open_options
          .read(true)
          .create(true)
          .write(true)
          .truncate(true);
      }
      "a" => {
        open_options.create(true).append(true);
      }
      "a+" => {
        open_options.read(true).create(true).append(true);
      }
      "x" => {
        open_options.create_new(true).write(true);
      }
      "x+" => {
        open_options.create_new(true).read(true).write(true);
      }
      &_ => {
        // TODO: this should be type error
        return Err(OpError::other("Unknown open mode.".to_string()));
      }
    }
  } else {
    return Err(OpError::other(
      "Open requires either openMode or options.".to_string(),
    ));
  };

  let is_sync = args.promise_id.is_none();
  // op_open, notblocking_json
  let fut = async move {
    let fs_file = open_options.open(path).await?;
    let mut state = state_.borrow_mut();
    let rid = state.resource_table.add(
      "fsFile",
      Box::new(StreamResource::FsFile(fs_file, FileMetadata::default())),
    );
    Ok(json!(rid))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeekArgs {
  promise_id: Option<u64>,
  rid: i32,
  offset: i64,
  whence: i32,
}

fn op_seek(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: SeekArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  let offset = args.offset;
  let whence = args.whence;
  // Translate seek mode to Rust repr.
  let seek_from = match whence {
    0 => {
      // require offset to be 63 bit unsigned
      let offset: u64 = offset.try_into()?;
      io::SeekFrom::Start(offset)
    }
    1 => io::SeekFrom::Current(offset),
    2 => io::SeekFrom::End(offset),
    _ => {
      return Err(OpError::type_error(format!(
        "Invalid seek mode: {}",
        whence
      )));
    }
  };

  let state = state.borrow();
  let resource = state
    .resource_table
    .get::<StreamResource>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let mut file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  // op_seek, notblocking_json
  let fut = async move {
    debug!("op_seek {} {} {}", rid, offset, whence);
    let pos = file.seek(seek_from).await?;
    Ok(json!(pos))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncArgs {
  rid: i32,
}

fn op_sync(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: SyncArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  let state = state.borrow();
  let resource = state
    .resource_table
    .get::<StreamResource>(rid)
    .ok_or_else(OpError::bad_resource_id)?;
  let tokio_file = match resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let mut file = futures::executor::block_on(tokio_file.try_clone())?;
  debug!("sync {}", rid);
  futures::executor::block_on(file.sync_all())?;
  Ok(JsonOp::Sync(json!({})))
}

fn op_datasync(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: SyncArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  let state = state.borrow();
  let resource = state
    .resource_table
    .get::<StreamResource>(rid)
    .ok_or_else(OpError::bad_resource_id)?;
  let tokio_file = match resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let mut file = futures::executor::block_on(tokio_file.try_clone())?;
  debug!("datasync {}", rid);
  futures::executor::block_on(file.sync_data())?;
  Ok(JsonOp::Sync(json!({})))
}

#[derive(Deserialize)]
struct UmaskArgs {
  mask: Option<u32>,
}

fn op_umask(
  _state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: UmaskArgs = serde_json::from_value(args)?;
  // TODO implement umask for Windows
  // see https://github.com/nodejs/node/blob/master/src/node_process_methods.cc
  // and https://docs.microsoft.com/fr-fr/cpp/c-runtime-library/reference/umask?view=vs-2019
  #[cfg(not(unix))]
  {
    let _ = args.mask; // avoid unused warning.
    return Err(OpError::not_implemented());
  }
  #[cfg(unix)]
  {
    use nix::sys::stat::mode_t;
    use nix::sys::stat::umask;
    use nix::sys::stat::Mode;
    let r = if let Some(mask) = args.mask {
      // If mask provided, return previous.
      umask(Mode::from_bits_truncate(mask as mode_t))
    } else {
      // If no mask provided, we query the current. Requires two syscalls.
      let prev = umask(Mode::from_bits_truncate(0o777));
      let _ = umask(prev);
      prev
    };
    Ok(JsonOp::Sync(json!(r.bits() as u32)))
  }
}

#[derive(Deserialize)]
struct ChdirArgs {
  directory: String,
}

fn op_chdir(
  _state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ChdirArgs = serde_json::from_value(args)?;
  env::set_current_dir(&args.directory)?;
  Ok(JsonOp::Sync(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MkdirArgs {
  promise_id: Option<u64>,
  path: String,
  recursive: bool,
  mode: Option<u32>,
}

fn op_mkdir(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: MkdirArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let mode = args.mode.unwrap_or(0o777);

  state.check_write(&path)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_mkdir {} {:o} {}", path.display(), mode, args.recursive);
    if args.recursive {
      tokio_fs::create_dir_all(&path).await?;
    } else {
      tokio_fs::create_dir(&path).await?;
    }
    #[cfg(not(unix))]
    {
      use std::os::unix::fs::PermissionsExt;
      let metadata = tokio_fs::metadata(&path).await?;
      let mut permissions = metadata.permissions();
      permissions.set_mode(mode);
      match tokio_fs::set_permissions(&path, permissions).await {
        Ok(()) => (),
        Err(e) => {
          tokio_fs::remove_dir(path).await?;
          return Err(e);
        }
      }
    }
    /*
    let mut builder = std_fs::DirBuilder::new();
    builder.recursive(args.recursive);
    set_dir_permissions(&mut builder, mode);
    builder.create(path)?;
    */
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChmodArgs {
  promise_id: Option<u64>,
  path: String,
  mode: u32,
}

fn op_chmod(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ChmodArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  #[allow(unused)]
  let mode = args.mode & 0o777;

  state.check_write(&path)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    // Still check file/dir exists on windows
    let _metadata = tokio_fs::metadata(&path).await?;
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      debug!("op_chmod {} {:o}", path.display(), mode);
      let mut permissions = _metadata.permissions();
      permissions.set_mode(mode);
      tokio_fs::set_permissions(&path, permissions).await?;
    }
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChownArgs {
  promise_id: Option<u64>,
  path: String,
  uid: u32,
  gid: u32,
}

fn op_chown(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ChownArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;

  state.check_write(&path)?;

  let is_sync = args.promise_id.is_none();
  // CANTFIX
  blocking_json(is_sync, move || {
    debug!("op_chown {} {} {}", path.display(), args.uid, args.gid);
    #[cfg(unix)]
    {
      use nix::unistd::{chown, Gid, Uid};
      let path: &str = args.path.as_ref();
      let nix_uid = Uid::from_raw(args.uid);
      let nix_gid = Gid::from_raw(args.gid);
      chown(path, Option::Some(nix_uid), Option::Some(nix_gid))
        .map_err(ErrBox::from)?;
    }
    #[cfg(not(unix))]
    {
      // TODO: implement chown for Windows
      let e = io::Error::new(io::ErrorKind::Other, "Not implemented".to_string());
      return Err(ErrBox::from(e));
    }
    Ok(json!({}))
  })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveArgs {
  promise_id: Option<u64>,
  path: String,
  recursive: bool,
}

fn op_remove(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: RemoveArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let recursive = args.recursive;

  state.check_write(&path)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    let metadata = tokio_fs::symlink_metadata(&path).await?;
    debug!("op_remove {} {}", path.display(), recursive);
    let file_type = metadata.file_type();
    if file_type.is_file() || file_type.is_symlink() {
      tokio_fs::remove_file(&path).await?;
    } else if recursive {
      tokio_fs::remove_dir_all(&path).await?;
    } else {
      tokio_fs::remove_dir(&path).await?;
    }
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CopyFileArgs {
  promise_id: Option<u64>,
  from: String,
  to: String,
  create: bool,
  create_new: bool,
}

fn op_copy_file(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: CopyFileArgs = serde_json::from_value(args)?;
  let from = resolve_from_cwd(Path::new(&args.from))?;
  let to = resolve_from_cwd(Path::new(&args.to))?;
  let create = args.create;
  let create_new = args.create_new;

  state.check_read(&from)?;
  state.check_write(&to)?;

  let is_sync = args.promise_id.is_none();
  // FIXME
  blocking_json(is_sync, move || {
    debug!("op_copy_file {} {}", from.display(), to.display());
    // On *nix, Rust reports non-existent `from` as io::ErrorKind::InvalidInput
    // See https://github.com/rust-lang/rust/issues/54800
    // Once the issue is resolved, we should remove this workaround.
    if cfg!(unix) && !from.is_file() {
      return Err(OpError::not_found("File not found".to_string()));
    }

    if create && !create_new {
      // default, most efficient version -- data never copied out of kernel space
      // returns length of from as u64 (we ignore)
      std_fs::copy(&from, &to)?;
    } else {
      let mut from_file = std_fs::OpenOptions::new().read(true).open(&from)?;
      let mut open_options = std_fs::OpenOptions::new();
      open_options
        .create(create)
        .create_new(create_new)
        .write(true);
      let mut to_file = open_options.open(&to)?;
      let from_meta = from_file.metadata()?;
      to_file.set_permissions(from_meta.permissions())?;
      // returns length of from as u64 (we ignore)
      io::copy(&mut from_file, &mut to_file)?;
    }
    Ok(json!({}))
  })
}

macro_rules! to_seconds {
  ($time:expr) => {{
    // Unwrap is safe here as if the file is before the unix epoch
    // something is very wrong.
    $time
      .and_then(|t| Ok(t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64))
      .unwrap_or(0)
  }};
}

#[inline(always)]
fn get_stat_json(
  metadata: std_fs::Metadata,
  maybe_name: Option<String>,
) -> JsonResult {
  // Unix stat member (number types only). 0 if not on unix.
  macro_rules! usm {
    ($member: ident) => {{
      #[cfg(unix)]
      {
        metadata.$member()
      }
      #[cfg(not(unix))]
      {
        0
      }
    }};
  }

  #[cfg(unix)]
  use std::os::unix::fs::MetadataExt;
  let mut json_val = json!({
    "isFile": metadata.is_file(),
    "isDir": metadata.is_dir(),
    "isSymlink": metadata.file_type().is_symlink(),
    "size": metadata.len(),
    // In seconds (i64). Available on both Unix or Windows.
    "modified":to_seconds!(metadata.modified()), // changed when fdatasync
    "accessed":to_seconds!(metadata.accessed()),
    "created":to_seconds!(metadata.created()),
    // Following are only valid under Unix.
    "ctime": usm!(ctime), // i64, changed when fdatasync or chown/chmod/rename/moved
    "dev": usm!(dev), // u64
    "ino": usm!(ino), // u64
    "mode": usm!(mode), // usually u32, may be u16 on Mac
    "nlink": usm!(nlink), // u64
    "uid": usm!(uid), // u32
    "gid": usm!(gid), // u32
    "rdev": usm!(rdev), // u64
    // TODO(kevinkassimo): *time_nsec requires BigInt.
    // Probably should be treated as String if we need to add them.
    "blksize": usm!(blksize) as i64, // was u64
    "blocks": usm!(blocks) as i64, // was u64
  });

  // "name" is an optional field by our design.
  if let Some(name) = maybe_name {
    if let serde_json::Value::Object(ref mut m) = json_val {
      m.insert("name".to_owned(), json!(name));
    }
  }

  Ok(json_val)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatArgs {
  promise_id: Option<u64>,
  path: String,
  lstat: bool,
}

fn op_stat(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: StatArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let lstat = args.lstat;

  state.check_read(&path)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_stat {} {}", path.display(), lstat);
    let metadata = if lstat {
      tokio_fs::symlink_metadata(&path).await?
    } else {
      tokio_fs::metadata(&path).await?
    };
    get_stat_json(metadata, None)
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealpathArgs {
  promise_id: Option<u64>,
  path: String,
}

fn op_realpath(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: RealpathArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;

  state.check_read(&path)?;

  // op_realpath, notblocking_json
  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_realpath {}", path.display());
    // corresponds to the realpath on Unix and
    // CreateFile and GetFinalPathNameByHandle on Windows
    let realpath = tokio_fs::canonicalize(&path).await?;
    let mut realpath_str =
      realpath.to_str().unwrap().to_owned().replace("\\", "/");
    if cfg!(windows) {
      realpath_str = realpath_str.trim_start_matches("//?/").to_string();
    }
    Ok(json!(realpath_str))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
  /*
  Blocking_json(is_sync, move || {
    debug!("op_realpath {}", path.display());
    // corresponds to the realpath on Unix and
    // CreateFile and GetFinalPathNameByHandle on Windows
    let realpath = std_fs::canonicalize(&path)?;
    let mut realpath_str =
      realpath.to_str().unwrap().to_owned().replace("\\", "/");
    if cfg!(windows) {
      realpath_str = realpath_str.trim_start_matches("//?/").to_string();
    }
    Ok(json!(realpath_str))
  })
   */
  /*
  tokio_json(is_sync, async || {
    debug!("op_realpath {}", path.display());
    // corresponds to the realpath on Unix and
    // CreateFile and GetFinalPathNameByHandle on Windows
    let realpath = tokio_fs::canonicalize(&path).await?;
    let mut realpath_str =
      realpath.to_str().unwrap().to_owned().replace("\\", "/");
    if cfg!(windows) {
      realpath_str = realpath_str.trim_start_matches("//?/").to_string();
    }
    Ok(json!(realpath_str))
  })

#[allow(dead_code)]
pub fn tokio_json<F>(is_sync: bool, f: F) -> Result<JsonOp, OpError>
where
  F: 'static + Send + FnOnce() -> JsonResult,
{
  let fut = async move { f() }.boxed_local();
  if is_sync {
    let result = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(result))
  } else {
    Ok(JsonOp::Async(fut))
  }
}
   */
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadDirArgs {
  promise_id: Option<u64>,
  path: String,
}

fn op_read_dir(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ReadDirArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;

  state.check_read(&path)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_read_dir {}", path.display());
    let mut entries = Vec::new();
    let mut stream = tokio_fs::read_dir(path).await?;
    while let Some(entry) = stream.next_entry().await? {
      let metadata = entry.metadata().await.unwrap();
      // Not all filenames can be encoded as UTF-8. Skip those for now.
      if let Some(filename) = entry.file_name().to_str() {
        let filename = Some(filename.to_owned());
        entries.push(get_stat_json(metadata, filename).unwrap());
      }
    }
    Ok(json!({ "entries": entries }))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenameArgs {
  promise_id: Option<u64>,
  oldpath: String,
  newpath: String,
  create_new: bool,
}

fn op_rename(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: RenameArgs = serde_json::from_value(args)?;
  let oldpath = resolve_from_cwd(Path::new(&args.oldpath))?;
  let newpath = resolve_from_cwd(Path::new(&args.newpath))?;

  state.check_read(&oldpath)?;
  state.check_write(&oldpath)?;
  state.check_write(&newpath)?;

  let is_sync = args.promise_id.is_none();
  // FIXME
  blocking_json(is_sync, move || {
    debug!("op_rename {} {}", oldpath.display(), newpath.display());
    if args.create_new {
      let mut open_options = std_fs::OpenOptions::new();
      open_options.write(true).create_new(true);
      open_options.open(&newpath)?;
    }
    std_fs::rename(&oldpath, &newpath)?;
    Ok(json!({}))
  })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkArgs {
  promise_id: Option<u64>,
  oldname: String,
  newname: String,
}

fn op_link(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: LinkArgs = serde_json::from_value(args)?;
  let oldname = resolve_from_cwd(Path::new(&args.oldname))?;
  let newname = resolve_from_cwd(Path::new(&args.newname))?;

  state.check_read(&oldname)?;
  state.check_write(&newname)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_link {} {}", oldname.display(), newname.display());
    tokio_fs::hard_link(&oldname, &newname).await?;
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SymlinkArgs {
  promise_id: Option<u64>,
  oldname: String,
  newname: String,
}

fn op_symlink(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: SymlinkArgs = serde_json::from_value(args)?;
  #[allow(unused)]
  let oldname = resolve_from_cwd(Path::new(&args.oldname))?;
  let newname = resolve_from_cwd(Path::new(&args.newname))?;

  state.check_write(&newname)?;
  // TODO Use type for Windows.
  if cfg!(not(unix)) {
    return Err(OpError::other("Not implemented".to_string()));
  }

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    #[cfg(unix)]
    {
      // use std::os::unix::fs::symlink;
      use tokio_fs::os::unix::symlink;
      debug!("op_symlink {} {}", oldname.display(), newname.display());
      symlink(&oldname, &newname).await?;
    }
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadLinkArgs {
  promise_id: Option<u64>,
  path: String,
}

fn op_read_link(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ReadLinkArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;

  state.check_read(&path)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_read_link {}", path.display());
    let path = tokio_fs::read_link(&path).await?;
    let path_str = path.to_str().unwrap();
    Ok(json!(path_str))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TruncateArgs {
  promise_id: Option<u64>,
  path: String,
  len: i64,
  mode: Option<u32>,
  create: bool,
  create_new: bool,
}

fn op_truncate(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: TruncateArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  // require len to be 63 bit unsigned
  let len: u64 = args.len.try_into()?;
  let create = args.create;
  let create_new = args.create_new;

  state.check_write(&path)?;

  let is_sync = args.promise_id.is_none();
  // FIXME
  blocking_json(is_sync, move || {
    debug!("op_truncate {} {}", path.display(), len);
    let mut open_options = std_fs::OpenOptions::new();
    if let Some(_mode) = args.mode {
      if !(create || create_new) {
        return Err(OpError::type_error(
          "specified mode without allowing file creation".to_string(),
        ));
      }
      // mode only used if creating the file on Unix
      // if not specified, defaults to 0o666
      #[cfg(unix)]
      {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(_mode & 0o777);
      }
    }
    open_options
      .create(create)
      .create_new(create_new)
      .write(true);
    let f = open_options.open(&path)?;
    f.set_len(len)?;
    Ok(json!({}))
  })
}

///////////
pub fn my_make_temp(
  dir: Option<&Path>,
  prefix: Option<&str>,
  suffix: Option<&str>,
  is_dir: bool,
) -> io::Result<PathBuf> {
  let prefix_ = prefix.unwrap_or("");
  let suffix_ = suffix.unwrap_or("");
  let mut buf: PathBuf = match dir {
    Some(ref p) => p.to_path_buf(),
    None => env::temp_dir(),
  }
  .join("_");
  let mut rng = thread_rng();
  loop {
    let unique = rng.gen::<u32>();
    buf.set_file_name(format!("{}{:08x}{}", prefix_, unique, suffix_));
    let r = if is_dir {
      let mut builder = std_fs::DirBuilder::new();
      set_dir_permissions(&mut builder, 0o700);
      builder.create(buf.as_path())
    } else {
      let mut open_options = std_fs::OpenOptions::new();
      open_options.write(true).create_new(true);
      #[cfg(unix)]
      {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
      }
      open_options.open(buf.as_path())?;
      Ok(())
    };
    match r {
      Err(ref e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
      Ok(_) => return Ok(buf),
      Err(e) => return Err(e),
    }
  }
}
///////////

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeTempArgs {
  promise_id: Option<u64>,
  dir: Option<String>,
  prefix: Option<String>,
  suffix: Option<String>,
}

fn op_make_temp_dir(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: MakeTempArgs = serde_json::from_value(args)?;

  let dir = args
    .dir
    .map(|s| resolve_from_cwd(Path::new(&s)).unwrap());
  let prefix = args.prefix.map(String::from);
  let suffix = args.suffix.map(String::from);

  state
    .check_write(dir.clone().unwrap_or_else(env::temp_dir).as_path())?;

  let is_sync = args.promise_id.is_none();
  // FIXME
  blocking_json(is_sync, move || {
    // TODO(piscisaureus): use byte vector for paths, not a string.
    // See https://github.com/denoland/deno/issues/627.
    // We can't assume that paths are always valid utf8 strings.
    let path = my_make_temp(
      // Converting Option<String> to Option<&str>
      dir.as_ref().map(|x| &**x),
      prefix.as_ref().map(|x| &**x),
      suffix.as_ref().map(|x| &**x),
      true,
    )?;
    let path_str = path.to_str().unwrap();

    Ok(json!(path_str))
  })
}

fn op_make_temp_file(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: MakeTempArgs = serde_json::from_value(args)?;

  let dir = args
    .dir
    .map(|s| resolve_from_cwd(Path::new(&s)).unwrap());
  let prefix = args.prefix.map(String::from);
  let suffix = args.suffix.map(String::from);

  state
    .check_write(dir.clone().unwrap_or_else(env::temp_dir).as_path())?;

  let is_sync = args.promise_id.is_none();
  // FIXME
  blocking_json(is_sync, move || {
    // TODO(piscisaureus): use byte vector for paths, not a string.
    // See https://github.com/denoland/deno/issues/627.
    // We can't assume that paths are always valid utf8 strings.
    let path = my_make_temp(
      // Converting Option<String> to Option<&str>
      dir.as_ref().map(|x| &**x),
      prefix.as_ref().map(|x| &**x),
      suffix.as_ref().map(|x| &**x),
      false,
    )?;
    let path_str = path.to_str().unwrap();

    Ok(json!(path_str))
  })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UtimeArgs {
  promise_id: Option<u64>,
  path: String,
  atime: i64,
  mtime: i64,
}

fn op_utime(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: UtimeArgs = serde_json::from_value(args)?;
  state.check_write(Path::new(&args.path))?;
  // require times to be 63 bit unsigned
  let atime: u64 = args.atime.try_into()?;
  let mtime: u64 = args.mtime.try_into()?;

  let is_sync = args.promise_id.is_none();
  // CANTFIX
  blocking_json(is_sync, move || {
    debug!("op_utime {} {} {}", args.path, atime, mtime);
    set_file_times(args.path, atime, mtime)?;
    Ok(json!({}))
  })
}

fn op_cwd(
  _state: &State,
  _args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let path = env::current_dir()?;
  let path_str = path.into_os_string().into_string().unwrap();
  Ok(JsonOp::Sync(json!(path_str)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FTruncateArgs {
  promise_id: Option<u64>,
  rid: i32,
  len: i64,
}

fn op_ftruncate(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: FTruncateArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  // require len to be 63 bit unsigned
  let len: u64 = args.len.try_into()?;
  let state = state.borrow();
  let resource = state
    .resource_table
    .get::<StreamResource>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let mut file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  // op_ftruncate, notblocking_json
  let fut = async move {
    // Unix returns InvalidInput if fd was not opened for writing
    // For consistency with Windows, we check explicitly
    #[cfg(unix)]
    my_check_open_for_writing(&file)?;
    debug!("op_ftruncate {} {}", rid, len);
    file.set_len(len).await?;
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FChmodArgs {
  promise_id: Option<u64>,
  rid: i32,
  // #[allow(unused)]
  mode: u32,
}

fn op_fchmod(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  if cfg!(not(unix)) {
    return Err(OpError::other("Not implemented".to_string()));
  }
  let args: FChmodArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  #[allow(unused)]
  let mode = args.mode & 0o777;
  let state = state.borrow();
  let resource = state
    .resource_table
    .get::<StreamResource>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource {
    // TODO(jp): save metadata instead of re-querying later?
    StreamResource::FsFile(ref file, _metadata) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  #[allow(unused)]
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  // op_fchmod, notblocking_json
  let fut = async move {
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      my_check_open_for_writing(&file)?;
      debug!("op_fchmod {} {:o}", rid, mode);
      let metadata = file.metadata().await?;
      let mut permissions = metadata.permissions();
      permissions.set_mode(mode);
      file.set_permissions(permissions).await?;
    }
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

///////
#[cfg(unix)]
use nix::sys::stat::futimens;

#[cfg(unix)]
use nix::sys::time::{TimeSpec, TimeValLike};

#[cfg(unix)]
pub fn fset_file_times(
  fd: RawFd,
  atime: u64,
  mtime: u64,
) -> Result<(), ErrBox> {
  let atime = TimeSpec::seconds(atime as i64);
  let mtime = TimeSpec::seconds(mtime as i64);
  futimens(fd, &atime, &mtime).map_err(ErrBox::from)?;
  Ok(())
}
///////

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FUtimeArgs {
  promise_id: Option<u64>,
  rid: i32,
  atime: i64,
  mtime: i64,
}

fn op_futime(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  if cfg!(not(unix)) {
    return Err(OpError::other("Not implemented".to_string()));
  }
  let args: FUtimeArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  #[allow(unused)]
  let atime = args.atime;
  #[allow(unused)]
  let mtime = args.mtime;
  let state = state.borrow();
  let resource = state
    .resource_table
    .get::<StreamResource>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  #[allow(unused)]
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  // FIXME
  blocking_json(is_sync, move || {
    #[cfg(unix)]
    {
      let fd = my_check_open_for_writing(&file)?;
      // require times to be 63 bit unsigned
      let atime: u64 = args.atime.try_into()?;
      let mtime: u64 = args.mtime.try_into()?;
      debug!("op_futime {} {} {}", rid, atime, mtime);
      fset_file_times(fd, atime, mtime)?;
    }
    Ok(json!({}))
  })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FStatArgs {
  promise_id: Option<u64>,
  rid: i32,
}

fn op_fstat(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  if cfg!(not(unix)) {
    return Err(OpError::other("Not implemented".to_string()));
  }
  let args: FStatArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  let state = state.borrow();
  let resource = state
    .resource_table
    .get::<StreamResource>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource {
    // TODO(jp): save metadata instead of re-querying later?
    StreamResource::FsFile(ref file, _metadata) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  #[allow(unused)]
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  // op_fstat, notblocking_json
  let fut = async move {
    #[cfg(unix)]
    {
      debug!("op_fstat {}", rid);
      #[allow(unused)]
      let fd = my_check_open_for_reading(&file)?;
      /*
      let filestat: nix::sys::stat::FileStat = deno_fs::fstat(fd)?;
      let sflag = deno_fs::SFlag::from_bits_truncate(filestat.st_mode);
      // see https://unix.stackexchange.com/questions/91197
      // not available on Linux, and their
      // libc::statx(dirfd, &path, flags, mask, &statxbuf_with_stx_btime)
      // doesn't apply to fd
      #[cfg(target_os = "linux")]
      let birthtime: i64 = 0;
      #[cfg(not(target_os = "linux"))]
      let birthtime: i64 = filestat.st_birthtime;
      let json_val = json!({
        "size": filestat.st_size,
        "isFile": sflag.contains(deno_fs::SFlag::S_IFREG),
        "isDir": sflag.contains(deno_fs::SFlag::S_IFLNK),
        "isSymlink": sflag.contains(deno_fs::SFlag::S_IFDIR),
        // all times are i64
        "accessed": filestat.st_atime,
        "modified": filestat.st_mtime, // changed when fdatasync
        "created": birthtime,
        "ctime": filestat.st_ctime, // changed when fdatasync or chown/chmod/rename/moved
        "dev": filestat.st_dev, // u64
        "ino": filestat.st_ino, // u64
        "mode": filestat.st_mode, // usually u32, may be u16 on Mac
        "nlink": filestat.st_nlink, // u64
        "uid": filestat.st_uid, // u32
        "gid": filestat.st_gid, // u32
        "rdev": filestat.st_rdev, // u64
        "blksize": filestat.st_blksize, // i64
        "blocks": filestat.st_blocks, // i64
      });
      Ok(json_val)
       */
      let metadata = file.metadata().await?;
      get_stat_json(metadata, None)
    }
    #[cfg(not(unix))]
    Ok(json!({}))
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}
