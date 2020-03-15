// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
// Some deserializer fields are only used on Unix and Windows build fails without it
use super::dispatch_json::{blocking_json, Deserialize, JsonOp, Value};
use super::io::{FileMetadata, StreamResource, StreamResourceHolder};
use crate::fs::resolve_from_cwd;
use crate::op_error::OpError;
use crate::ops::dispatch_json::JsonResult;
use crate::state::State;
use deno_core::*;
use futures::future::FutureExt;
use std::convert::{From, TryInto};
use std::env::{current_dir, set_current_dir, temp_dir};
use std::io::{ErrorKind, Result as ioResult, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use tokio;

/*
 * TODO(jp)
 * Better tests for mkdir {mode}, with/without -p
 */

use rand::{thread_rng, Rng};
// use remove_dir_all::remove_dir_all; // TODO(jp)
use utime::set_file_times;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(unix)]
fn my_check_open_for_writing(file: &tokio::fs::File) -> Result<RawFd, OpError> {
  use nix::fcntl::{fcntl, FcntlArg, OFlag};
  let fd = file.as_raw_fd();
  let flags = fcntl(fd, FcntlArg::F_GETFL)?;
  let flags = OFlag::from_bits_truncate(flags);
  let mode = OFlag::O_ACCMODE & flags;
  if mode == OFlag::O_RDWR || mode == OFlag::O_WRONLY {
    Ok(fd)
  } else {
    let e = OpError::permission_denied(
      "run again with the --allow-write flag".to_string(),
    );
    Err(e)
  }
}

#[cfg(unix)]
fn my_check_open_for_reading(file: &tokio::fs::File) -> Result<RawFd, OpError> {
  use nix::fcntl::{fcntl, FcntlArg, OFlag};
  let fd = file.as_raw_fd();
  let flags = fcntl(fd, FcntlArg::F_GETFL)?;
  let flags = OFlag::from_bits_truncate(flags);
  let mode = OFlag::O_ACCMODE & flags;
  if mode == OFlag::O_RDWR || mode == OFlag::O_RDONLY {
    Ok(fd)
  } else {
    let e = OpError::permission_denied(
      "run again with the --allow-read flag".to_string(),
    );
    Err(e)
  }
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

fn tokio_open_options(mode: Option<u32>) -> tokio::fs::OpenOptions {
  if let Some(mode) = mode {
    #[allow(unused_mut)]
    let mut std_options = std::fs::OpenOptions::new();
    // mode only used if creating the file on Unix
    // if not specified, defaults to 0o666
    #[cfg(unix)]
    {
      use std::os::unix::fs::OpenOptionsExt;
      std_options.mode(mode & 0o777);
    }
    #[cfg(not(unix))]
    let _ = mode; // avoid unused warning
    tokio::fs::OpenOptions::from(std_options)
  } else {
    tokio::fs::OpenOptions::new()
  }
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

  let mut open_options = tokio_open_options(args.mode);

  if let Some(options) = args.options {
    if options.read {
      state.check_read(&path)?;
    }

    if options.write || options.append {
      state.check_write(&path)?;
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
  let fut = async move {
    let fs_file = open_options.open(path).await?;
    let mut state = state_.borrow_mut();
    let rid = state.resource_table.add(
      "fsFile",
      Box::new(StreamResourceHolder::new(StreamResource::FsFile(
        fs_file,
        FileMetadata::default(),
      ))),
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
      SeekFrom::Start(offset)
    }
    1 => SeekFrom::Current(offset),
    2 => SeekFrom::End(offset),
    _ => {
      return Err(OpError::type_error(format!(
        "Invalid seek mode: {}",
        whence
      )));
    }
  };

  let state = state.borrow();
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource_holder.resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let mut file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
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
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource_holder.resource {
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
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource_holder.resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let mut file = futures::executor::block_on(tokio_file.try_clone())?;

  debug!("datasync {}", rid);
  futures::executor::block_on(file.sync_data())?;
  Ok(JsonOp::Sync(json!({})))
}

#[cfg(unix)]
fn umask(mask: Option<u32>) -> u32 {
  use nix::sys::stat::mode_t;
  use nix::sys::stat::umask;
  use nix::sys::stat::Mode;
  let r = if let Some(mask) = mask {
    // If mask provided, return previous
    umask(Mode::from_bits_truncate(mask as mode_t))
  } else {
    // If no mask provided, we query the current (requires two syscalls)
    let prev = umask(Mode::from_bits_truncate(0o777));
    let _ = umask(prev);
    prev
  };
  r.bits() as u32
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
    Err(OpError::not_implemented())
  }
  #[cfg(unix)]
  Ok(JsonOp::Sync(json!(umask(args.mask))))
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
  set_current_dir(&args.directory)?;
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
  let mode = args.mode.unwrap_or(0o777) & 0o777;

  state.check_write(&path)?;

  let is_sync = args.promise_id.is_none();
  // op_mkdir
  /*
  blocking_json(is_sync, move || {
    debug!("op_mkdir {} {:o} {}", path.display(), mode, args.recursive);
    // #[allow(unused_mut)]
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(args.recursive);
    #[cfg(unix)]
    {
      use std::os::unix::fs::DirBuilderExt;
      builder.mode(mode);
    }
    builder.create(path)?;
    Ok(json!({}))
  })
  */
  let fut = async move {
    debug!("op_mkdir {} {:o} {}", path.display(), mode, args.recursive);
    if args.recursive {
      // exit early if dir already exists, so that we don't
      // try to apply mode and remove it on failure
      if path.is_dir() {
        return Ok(json!({}));
      }
      tokio::fs::create_dir_all(&path).await?;
    } else {
      tokio::fs::create_dir(&path).await?;
    }
    if args.mode.is_some() {
      #[cfg(unix)]
      {
        use std::os::unix::fs::PermissionsExt;
        /*
        let metadata = tokio::fs::metadata(&path).await?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode);
        */
        // we have to query (takes 2 syscalls) and apply umask by hand
        let permissions = PermissionsExt::from_mode(mode & !umask(None));
        match tokio::fs::set_permissions(&path, permissions).await {
          Ok(()) => (),
          Err(e) => {
            // couldn't apply mode, so remove_dir then propagate error
            // if dir already existed (and so might not be empty)
            // we'll already have exited (if args.recursive) or failed
            tokio::fs::remove_dir(path).await?;
            return Err(OpError::from(e));
          }
        }
      }
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
  let mode = args.mode & 0o777;

  state.check_write(&path)?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    // Still check file/dir exists on windows
    let _metadata = tokio::fs::metadata(&path).await?;
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      debug!("op_chmod {} {:o}", path.display(), mode);
      /*
      let mut permissions = _metadata.permissions();
      permissions.set_mode(mode);
      */
      let permissions = PermissionsExt::from_mode(mode);
      tokio::fs::set_permissions(&path, permissions).await?;
    }
    #[cfg(not(unix))]
    let _ = mode; // avoid unused warning
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
  // CANTFIX, chown
  blocking_json(is_sync, move || {
    debug!("op_chown {} {} {}", path.display(), args.uid, args.gid);
    #[cfg(unix)]
    {
      use nix::unistd::{chown, Gid, Uid};
      let path: &str = args.path.as_ref();
      let nix_uid = Uid::from_raw(args.uid);
      let nix_gid = Gid::from_raw(args.gid);
      chown(path, Option::Some(nix_uid), Option::Some(nix_gid))?;
      Ok(json!({}))
    }
    #[cfg(not(unix))]
    {
      // TODO: implement chown for Windows
      Err(OpError::not_implemented())
    }
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
    let metadata = tokio::fs::symlink_metadata(&path).await?;
    debug!("op_remove {} {}", path.display(), recursive);
    let file_type = metadata.file_type();
    if file_type.is_file() || file_type.is_symlink() {
      tokio::fs::remove_file(&path).await?;
    } else if recursive {
      tokio::fs::remove_dir_all(&path).await?;
    } else {
      tokio::fs::remove_dir(&path).await?;
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
  let fut = async move {
    debug!("op_copy_file {} {}", from.display(), to.display());
    // On *nix, Rust reports non-existent `from` as std::io::ErrorKind::InvalidInput
    // See https://github.com/rust-lang/rust/issues/54800
    // Once the issue is resolved, we should remove this workaround.
    if cfg!(unix) && !from.is_file() {
      return Err(OpError::not_found("File not found".to_string()));
    }

    if create && !create_new {
      // default, most efficient version -- data never copied out of kernel space
      // returns size of from as u64 (we ignore)
      tokio::fs::copy(&from, &to).await?;
    } else {
      let mut from_file =
        tokio::fs::OpenOptions::new().read(true).open(&from).await?;
      let mut open_options = tokio::fs::OpenOptions::new();
      open_options
        .create(create)
        .create_new(create_new)
        .write(true);
      let mut to_file = open_options.open(&to).await?;
      let from_meta = from_file.metadata().await?;
      to_file.set_permissions(from_meta.permissions()).await?;
      // returns size of from as u64 (we ignore)
      tokio::io::copy(&mut from_file, &mut to_file).await?;
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
  metadata: std::fs::Metadata,
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
      tokio::fs::symlink_metadata(&path).await?
    } else {
      tokio::fs::metadata(&path).await?
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

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_realpath {}", path.display());
    // corresponds to the realpath on Unix and
    // CreateFile and GetFinalPathNameByHandle on Windows
    let realpath = tokio::fs::canonicalize(&path).await?;
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
    let realpath = std::fs::canonicalize(&path)?;
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
      let realpath = tokio::fs::canonicalize(&path).await?;
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
    let mut stream = tokio::fs::read_dir(path).await?;
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
  let fut = async move {
    debug!("op_rename {} {}", oldpath.display(), newpath.display());
    if args.create_new {
      let mut open_options = tokio::fs::OpenOptions::new();
      open_options.write(true).create_new(true);
      open_options.open(&newpath).await?;
    }
    tokio::fs::rename(&oldpath, &newpath).await?;
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
    tokio::fs::hard_link(&oldname, &newname).await?;
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
  let oldname = resolve_from_cwd(Path::new(&args.oldname))?;
  let newname = resolve_from_cwd(Path::new(&args.newname))?;

  state.check_write(&newname)?;
  // TODO Use type for Windows.
  if cfg!(not(unix)) {
    let _ = oldname; // avoid unused warning
    return Err(OpError::not_implemented());
  }

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    #[cfg(unix)]
    {
      use tokio::fs::os::unix::symlink;
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
    let path = tokio::fs::read_link(&path).await?;
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
  let fut = async move {
    if args.mode.is_some() && !(create || create_new) {
      return Err(OpError::type_error(
        "specified mode without allowing file creation".to_string(),
      ));
    }
    debug!("op_truncate {} {}", path.display(), len);
    let mut open_options = tokio_open_options(args.mode);
    open_options
      .create(create)
      .create_new(create_new)
      .write(true);
    let mut file = open_options.open(&path).await?;
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

fn make_temp(
  dir: Option<&Path>,
  prefix: Option<&str>,
  suffix: Option<&str>,
  is_dir: bool,
) -> ioResult<PathBuf> {
  let prefix_ = prefix.unwrap_or("");
  let suffix_ = suffix.unwrap_or("");
  let mut buf: PathBuf = match dir {
    Some(ref p) => p.to_path_buf(),
    None => temp_dir(),
  }
  .join("_");
  let mut rng = thread_rng();
  loop {
    let unique = rng.gen::<u32>();
    buf.set_file_name(format!("{}{:08x}{}", prefix_, unique, suffix_));
    // TODO(jp): tokio-ize?
    let r = if is_dir {
      #[allow(unused_mut)]
      let mut builder = std::fs::DirBuilder::new();
      #[cfg(unix)]
      {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
      }
      builder.create(buf.as_path())
    } else {
      let mut open_options = std::fs::OpenOptions::new();
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
      Err(ref e) if e.kind() == ErrorKind::AlreadyExists => continue,
      Ok(_) => return Ok(buf),
      Err(e) => return Err(e),
    }
  }
}

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

  let dir = args.dir.map(|s| resolve_from_cwd(Path::new(&s)).unwrap());
  let prefix = args.prefix.map(String::from);
  let suffix = args.suffix.map(String::from);

  state.check_write(dir.clone().unwrap_or_else(temp_dir).as_path())?;

  let is_sync = args.promise_id.is_none();
  // TODO(jp): op_make_temp_dir
  blocking_json(is_sync, move || {
    // TODO(piscisaureus): use byte vector for paths, not a string.
    // See https://github.com/denoland/deno/issues/627.
    // We can't assume that paths are always valid utf8 strings.
    let path = make_temp(
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

  let dir = args.dir.map(|s| resolve_from_cwd(Path::new(&s)).unwrap());
  let prefix = args.prefix.map(String::from);
  let suffix = args.suffix.map(String::from);

  state.check_write(dir.clone().unwrap_or_else(temp_dir).as_path())?;

  let is_sync = args.promise_id.is_none();
  // TODO(jp): op_make_temp_file
  blocking_json(is_sync, move || {
    // TODO(piscisaureus): use byte vector for paths, not a string.
    // See https://github.com/denoland/deno/issues/627.
    // We can't assume that paths are always valid utf8 strings.
    let path = make_temp(
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
  // CANTFIX, utime
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
  let path = current_dir()?;
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
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource_holder.resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let mut file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
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
  mode: u32,
}

fn op_fchmod(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  if cfg!(not(unix)) {
    return Err(OpError::not_implemented());
  }
  let args: FChmodArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  let mode = args.mode & 0o777;

  let state = state.borrow();
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource_holder.resource {
    // TODO(jp): save metadata instead of re-querying later?
    StreamResource::FsFile(ref file, _metadata) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      my_check_open_for_writing(&file)?;
      debug!("op_fchmod {} {:o}", rid, mode);
      /*
      let metadata = file.metadata().await?;
      let mut permissions = metadata.permissions();
      permissions.set_mode(mode);
      */
      let permissions = PermissionsExt::from_mode(mode);
      file.set_permissions(permissions).await?;
    }
    #[cfg(not(unix))]
    {
      let _ = mode; // avoid unused warning
      let _ = file;
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
    return Err(OpError::not_implemented());
  }
  let args: FUtimeArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;
  // require times to be 63 bit unsigned
  let atime: u64 = args.atime.try_into()?;
  let mtime: u64 = args.mtime.try_into()?;

  let state = state.borrow();
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource_holder.resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  // CANTFIX, op_futime
  blocking_json(is_sync, move || {
    #[cfg(unix)]
    {
      use nix::sys::stat::futimens;
      use nix::sys::time::{TimeSpec, TimeValLike};
      let fd = my_check_open_for_writing(&file)?;
      debug!("op_futime {} {} {}", rid, atime, mtime);
      let atime = TimeSpec::seconds(atime as i64);
      let mtime = TimeSpec::seconds(mtime as i64);
      futimens(fd, &atime, &mtime)?;
    }
    #[cfg(not(unix))]
    {
      let _ = file; // avoid unused warning
      let _ = atime;
      let _ = mtime;
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
    return Err(OpError::not_implemented());
  }
  let args: FStatArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;

  let state = state.borrow();
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_file = match resource_holder.resource {
    // TODO(jp): save metadata instead of re-querying later?
    StreamResource::FsFile(ref file, _metadata) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    #[cfg(unix)]
    {
      debug!("op_fstat {}", rid);
      let _fd = my_check_open_for_reading(&file)?;
      /*
      let filestat: nix::sys::stat::FileStat = deno_fs::fstat(_fd)?;
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
    {
      let _ = file; // avoid unused warning
      Ok(json!({}))
    }
  };

  if is_sync {
    let buf = futures::executor::block_on(fut)?;
    Ok(JsonOp::Sync(buf))
  } else {
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}
