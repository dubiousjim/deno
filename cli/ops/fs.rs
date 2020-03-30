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
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use tokio;

use rand::{thread_rng, Rng};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(unix)]
#[allow(unused_imports)]
use crate::nix_extra::faccessat;

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
  i.register_op("op_fchown", s.stateful_json_op(op_fchown));
  i.register_op("op_fchdir", s.stateful_json_op(op_fchdir));
}

fn tokio_open_options(
  mode: Option<u32>,
  nofollow: bool,
) -> tokio::fs::OpenOptions {
  if let Some(mode) = mode {
    #[allow(unused_mut)]
    let mut std_options = std::fs::OpenOptions::new();
    // mode only used if creating the file on Unix
    // if not specified, defaults to 0o666
    #[cfg(unix)]
    {
      use std::os::unix::fs::OpenOptionsExt;
      std_options.mode(mode & 0o777);
      if nofollow {
        std_options.custom_flags(libc::O_NOFOLLOW);
      }
    }
    #[cfg(not(unix))]
    {
      let _ = mode; // avoid unused warning
      let _ = nofollow;
    }
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
  nofollow: bool,
  #[allow(unused)]
  atrid: Option<i32>, // FIXME(jp5) open
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
  let nofollow = args.nofollow;
  let state_ = state.clone();

  let mut open_options = tokio_open_options(args.mode, nofollow);
  let mut create_new = false;

  if let Some(options) = args.options {
    let create = options.create;
    create_new = options.create_new;

    if args.mode.is_some() && !(create || create_new) {
      return Err(OpError::type_error(
        "specified mode without allowing file creation".to_string(),
      ));
    }

    if options.read {
      state.check_read(&path)?;
    }

    if options.write || options.append {
      state.check_write(&path)?;
      // require --allow-read to check whether `path` already exists
      if !create || create_new {
        state.check_read(&path)?;
      }
    }

    open_options
      .read(options.read)
      .create(create)
      .write(options.write)
      .truncate(options.truncate)
      .append(options.append)
      .create_new(create_new);
  } else if let Some(open_mode) = args.open_mode {
    let open_mode = open_mode.as_ref();
    match open_mode {
      "r" => {
        state.check_read(&path)?;
      }
      "w" | "a" => {
        state.check_write(&path)?;
        // these modes don't check whether `path` already exists
        // so --allow-read isn't required
      }
      "x" => {
        state.check_write(&path)?;
        // require --allow-read to check whether `path` already exists
        state.check_read(&path)?;
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
        create_new = true;
        open_options.create_new(true).write(true);
      }
      "x+" => {
        create_new = true;
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
    let fs_file = match open_options.open(&path).await {
      Err(e)
        if cfg!(windows)
          && create_new
          && e.kind() == std::io::ErrorKind::PermissionDenied
          && tokio::fs::metadata(&path).await.is_ok() =>
      {
        // alternately, "The file exists. (os error 80)"
        return Err(OpError::already_exists(
          "Cannot create a file when that file already exists. (os error 183)"
            .to_string(),
        ));
      }
      Err(e) => return Err(OpError::from(e)),
      Ok(f) => f,
    };
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
  // FIXME(jp1)
  // futures::executor::block_on(async move { file.sync_all().await })?;
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
  // FIXME(jp1)
  // futures::executor::block_on(async move { file.sync_data().await })?;
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
  path: String,
}

fn op_chdir(
  _state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ChdirArgs = serde_json::from_value(args)?;
  set_current_dir(&args.path)?;
  Ok(JsonOp::Sync(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MkdirArgs {
  promise_id: Option<u64>,
  path: String,
  recursive: bool,
  mode: Option<u32>,
  atrid: Option<i32>,
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

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!("op_mkdir {} {:o} {}", path.display(), mode, args.recursive);
    #[cfg(unix)]
    {
      use crate::nix_extra::{mkdirat, mode_t, Mode};
      let fd = atdir.map(|dir| dir.as_raw_fd());
      mkdirat(
        fd,
        &path,
        Mode::from_bits_truncate(mode as mode_t),
        args.recursive,
      )?;
    }
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning
      let mut builder = std::fs::DirBuilder::new();
      builder.recursive(args.recursive);
      builder.create(path)?;
    }
    Ok(json!({}))
    /*
    if args.recursive {
      // exit early if dir already exists, so that we don't
      // try to apply mode and remove dir on failure
      // like `mkdir -p`, we follow symlinks
      let metadata = tokio::fs::metadata(&path).await;
      if metadata.map_or(false, |m| m.is_dir()) {
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
        let mode = mode & !umask(None);
        // like `mkdir -p`, we permit u+wx regardless of umask
        let mode = mode | 0o300;
        let permissions = PermissionsExt::from_mode(mode);
        match tokio::fs::set_permissions(&path, permissions).await {
          Ok(()) => (),
          Err(e) => {
            // couldn't apply mode, so remove_dir then propagate error
            // if dir already existed (and so might not be empty)
            // we'll already have exited (if args.recursive) or failed
            tokio::fs::remove_dir(&path).await?;
            return Err(OpError::from(e));
          }
        }
      }
    }
    Ok(json!({}))
    */
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChmodArgs {
  promise_id: Option<u64>,
  path: String,
  mode: u32,
  nofollow: bool,
  atrid: Option<i32>,
}

fn op_chmod(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ChmodArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let nofollow = args.nofollow;
  let mode = args.mode & 0o777;

  state.check_write(&path)?;

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!("op_chmod {} {:o} {}", path.display(), mode, nofollow);
    #[cfg(unix)]
    {
      /*
       // futures::executor (async move) version
       use std::os::unix::fs::PermissionsExt;
       /*
       let metadata = tokio::fs::metadata(&path).await?;
       let mut permissions = metadata.permissions();
       permissions.set_mode(mode);
       */
       let permissions = PermissionsExt::from_mode(mode);
       tokio::fs::set_permissions(&path, permissions).await?;
      */
      use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
      #[cfg(target_os = "macos")]
      let mode: u16 = mode.try_into()?;
      let nix_mode = Mode::from_bits_truncate(mode);
      let flag = if nofollow {
        FchmodatFlags::NoFollowSymlink
      } else {
        FchmodatFlags::FollowSymlink
      };
      let fd = atdir.map(|dir| dir.as_raw_fd());
      fchmodat(fd, &path, nix_mode, flag)?;
      Ok(json!({}))
    }
    // TODO Implement chmod for Windows (#4357)
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning

      // Still check file/dir exists on Windows
      let _metadata = std::fs::metadata(&path)?;
      Err(OpError::not_implemented())
    }
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChownArgs {
  promise_id: Option<u64>,
  path: String,
  uid: Option<u32>,
  gid: Option<u32>,
  nofollow: bool,
  atrid: Option<i32>,
}

fn op_chown(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ChownArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let nofollow = args.nofollow;

  state.check_write(&path)?;

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3)
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!(
      "op_chown {} {} {} {}",
      path.display(),
      args.uid.unwrap_or(0xffff_ffff),
      args.gid.unwrap_or(0xffff_ffff),
      nofollow
    );
    #[cfg(unix)]
    {
      use nix::unistd::{fchownat, FchownatFlags, Gid, Uid};
      let nix_uid = args.uid.map(Uid::from_raw);
      let nix_gid = args.gid.map(Gid::from_raw);
      let flag = if nofollow {
        FchownatFlags::NoFollowSymlink
      } else {
        FchownatFlags::FollowSymlink
      };
      let fd = atdir.map(|dir| dir.as_raw_fd());
      fchownat(fd, &path, nix_uid, nix_gid, flag)?;
      Ok(json!({}))
    }
    // TODO Implement chown for Windows
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning
                     // Still check file/dir exists on Windows
      let _metadata = std::fs::metadata(&path)?;
      Err(OpError::not_implemented())
    }
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveArgs {
  promise_id: Option<u64>,
  path: String,
  recursive: bool,
  atrid: Option<i32>,
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

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!("op_remove {} {}", path.display(), recursive);
    #[cfg(unix)]
    {
      use crate::nix_extra::{cstr, filetypeat, unlinkat, UnlinkatFlags};
      let fd = match atdir {
        Some(dir) => dir.as_raw_fd(),
        None => libc::AT_FDCWD,
      };
      let cpath = cstr(&path)?;
      let flag = if filetypeat(fd, &cpath, true)? != libc::S_IFDIR {
        UnlinkatFlags::NoRemoveDir
      } else if recursive {
        UnlinkatFlags::RemoveDirAll
      } else {
        UnlinkatFlags::RemoveDir
      };
      unlinkat(Some(fd), &path, flag)?;
    }
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning
      let metadata = std::fs::symlink_metadata(&path)?;
      let file_type = metadata.file_type();
      if file_type.is_file() || file_type.is_symlink() {
        std::fs::remove_file(&path)?;
      } else if recursive {
        std::fs::remove_dir_all(&path)?;
      } else {
        std::fs::remove_dir(&path)?;
      }
    }
    Ok(json!({}))
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
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
  // require --allow-read to check whether `to` already exists
  if !create || create_new {
    state.check_read(&to)?;
  }

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_copy_file {} {}", from.display(), to.display());
    let mut from_file =
      tokio::fs::OpenOptions::new().read(true).open(&from).await?;
    let from_meta = from_file.metadata().await?;
    if cfg!(unix) && from_meta.is_dir() {
      // when copyFile("dir", ...), prioritize "Is a directory" error for `from`
      // over NotFound (from !create) or AlreadyExists (from createNew) errors for `to`
      return Err(OpError::other("Is a directory (os error 21)".to_string()));
    }
    let mut open_options = tokio::fs::OpenOptions::new();
    open_options
      .create(create)
      .create_new(create_new)
      .truncate(true)
      .write(true);
    let mut to_file = match open_options.open(&to).await {
      Err(e) if cfg!(unix) && e.kind() == std::io::ErrorKind::AlreadyExists => {
        match tokio::fs::metadata(&to).await {
          Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // `to` is dangling symlink
            // we handle the same as std::fs::copy does
            // namely, create the target and "copy through" to it
            // Python's shutil.copy and Node's fs.copyFileSync do the same
            // OTOH, `cp -T` in shell will fail when target is dangling symlink
            open_options.create_new(false);
            open_options.open(to).await?
          }
          _ => return Err(OpError::from(e)),
        }
      }
      Err(e)
        if cfg!(windows)
          && create_new
          && e.kind() == std::io::ErrorKind::PermissionDenied
          && tokio::fs::metadata(to).await.map_or(false, |m| m.is_dir()) =>
      {
        // alternately, "The file exists. (os error 80)"
        return Err(OpError::already_exists(
          "Cannot create a file when that file already exists. (os error 183)"
            .to_string(),
        ));
      }
      Err(e) => return Err(OpError::from(e)),
      Ok(f) => f,
    };
    // returns size of from as u64 (we ignore)
    tokio::io::copy(&mut from_file, &mut to_file).await?;
    to_file.set_permissions(from_meta.permissions()).await?;
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
  nofollow: bool,
  atrid: Option<i32>,
}

fn op_stat(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: StatArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let nofollow = args.nofollow;

  state.check_read(&path)?;

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!("op_stat {} {}", path.display(), nofollow);
    #[cfg(unix)]
    {
      use crate::nix_extra::{fstatat, /*ExtraStat, FileStat,*/ SFlag};
      let fd = atdir.map(|dir| dir.as_raw_fd());
      let extrastat = fstatat(fd, &path, nofollow)?;
      let filestat = extrastat.stat;
      let sflag = SFlag::from_bits_truncate(filestat.st_mode);
      let json_val = json!({
        "isFile": sflag == SFlag::S_IFREG,
        "isDir": sflag == SFlag::S_IFDIR,
        "isSymlink": sflag == SFlag::S_IFLNK,
        "size": filestat.st_size,
        // all times are i64
        "modified": filestat.st_mtime, // changed when fdatasync
        "accessed": filestat.st_atime,
        "created": extrastat.st_btime,
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
    }
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning
      let metadata = if nofollow {
        std::fs::symlink_metadata(&path)?
      } else {
        std::fs::metadata(&path)?
      };
      get_stat_json(metadata, None)
    }
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
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
    let mut stream = tokio::fs::read_dir(&path).await?;
    while let Some(entry) = stream.next_entry().await? {
      let metadata = entry.metadata().await?;
      // Not all filenames can be encoded as UTF-8. Skip those for now.
      if let Some(filename) = entry.file_name().to_str() {
        let filename = Some(filename.to_owned());
        entries.push(get_stat_json(metadata, filename)?);
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
  oldatrid: Option<i32>,
  newatrid: Option<i32>,
}

fn op_rename(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: RenameArgs = serde_json::from_value(args)?;
  let oldpath = resolve_from_cwd(Path::new(&args.oldpath))?;
  let newpath = resolve_from_cwd(Path::new(&args.newpath))?;
  let create_new = args.create_new;

  state.check_read(&oldpath)?;
  state.check_write(&oldpath)?;
  state.check_write(&newpath)?;
  // require --allow-read to check whether `newpath` already exists
  if create_new {
    state.check_read(&newpath)?;
  }

  let oldatdir = match args.oldatrid {
    Some(oldatrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(oldatrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  let newatdir = match args.newatrid {
    Some(newatrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(newatrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // TODO(jp5) rename (complex)
  let _ = oldatdir; // avoid unused warning
  let _ = newatdir;

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!("op_rename {} {}", oldpath.display(), newpath.display());
    /////
    #[cfg(unix)]
    {
      let _ = atdir; // avoid unused warning
      if create_new {
        // like `mv -Tn`, we don't follow symlinks
        let old_meta = std::fs::symlink_metadata(&oldpath)?;
        if old_meta.is_dir() {
          // on Unix, mv from dir to file always fails, but to emptydir is ok
          std::fs::create_dir(&newpath)?;
        } else {
          /*
          let mut open_options = std::fs::OpenOptions::new();
          open_options.write(true).create_new(true);
          if let Err(e) = open_options.open(&newpath) {
            return Err(OpError::from(e));
          }
          */
        }
      }
      std::fs::rename(&oldpath, &newpath)?;
    }
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning
      if create_new {
        // on Windows, mv from dir to dir always fails, but to file is ok
        let mut open_options = std::fs::OpenOptions::new();
        open_options.write(true).create_new(true);
        if let Err(e) = open_options.open(&newpath) {
          // if newpath.is_dir(), prefer to fail with AlreadyExists
          if e.kind() == std::io::ErrorKind::PermissionDenied
            && std::fs::metadata(&newpath).map_or(false, |m| m.is_dir())
          {
            // alternately, "The file exists. (os error 80)"
            return Err(OpError::already_exists("Cannot create a file when that file already exists. (os error 183)".to_string()));
          }
          return Err(OpError::from(e));
        }
      }
      std::fs::rename(&oldpath, &newpath)?;
    }
    Ok(json!({}))
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkArgs {
  promise_id: Option<u64>,
  oldpath: String,
  newpath: String,
  nofollow: bool,
  oldatrid: Option<i32>,
  newatrid: Option<i32>,
}

fn op_link(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: LinkArgs = serde_json::from_value(args)?;
  let oldpath = resolve_from_cwd(Path::new(&args.oldpath))?;
  let newpath = resolve_from_cwd(Path::new(&args.newpath))?;
  let nofollow = args.nofollow;

  state.check_read(&oldpath)?;
  state.check_write(&newpath)?;

  let oldatdir = match args.oldatrid {
    Some(oldatrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(oldatrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };
  let newatdir = match args.newatrid {
    Some(newatrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(newatrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!(
      "op_link {} {} {}",
      oldpath.display(),
      newpath.display(),
      nofollow
    );
    /*
       // futures::executor (async move) version
       tokio::fs::hard_link(&oldpath, &newpath).await?;
    */
    #[cfg(unix)]
    {
      use nix::unistd::{linkat, LinkatFlags};
      // the names of these flags are inverted relative to others
      let flag = if nofollow {
        LinkatFlags::NoSymlinkFollow
      } else {
        LinkatFlags::SymlinkFollow
      };
      let oldfd = oldatdir.map(|dir| dir.as_raw_fd());
      let newfd = newatdir.map(|dir| dir.as_raw_fd());
      linkat(oldfd, &oldpath, newfd, &newpath, flag)?;
    }
    #[cfg(not(unix))]
    {
      let _ = oldatdir; // avoid unused warning
      let _ = newatdir;
      std::fs::hard_link(&oldpath, &newpath)?;
    }
    Ok(json!({}))
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SymlinkArgs {
  promise_id: Option<u64>,
  oldpath: String,
  newpath: String,
  atrid: Option<i32>,
}

fn op_symlink(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: SymlinkArgs = serde_json::from_value(args)?;
  let oldpath = resolve_from_cwd(Path::new(&args.oldpath))?;
  let newpath = resolve_from_cwd(Path::new(&args.newpath))?;

  state.check_write(&newpath)?;

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!("op_symlink {} {}", oldpath.display(), newpath.display());
    #[cfg(unix)]
    {
      /*
      use std::fs::os::unix::symlink;
      symlink(&oldpath, &newpath)?;
      */
      use nix::unistd::symlinkat;
      let fd = atdir.map(|dir| dir.as_raw_fd());
      symlinkat(&oldpath, fd, &newpath)?;
      Ok(json!({}))
    }
    // TODO Implement symlink, use type for Windows
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning

      // Unlike with chmod/chown, here we don't
      // require `oldpath` to exist on Windows
      let _ = oldpath;
      Err(OpError::not_implemented())
    }
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadLinkArgs {
  promise_id: Option<u64>,
  path: String,
  atrid: Option<i32>,
}

fn op_read_link(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: ReadLinkArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;

  state.check_read(&path)?;

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3) mixed blocking
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!("op_read_link {}", path.display());
    let ostarget: std::ffi::OsString;
    #[cfg(unix)]
    {
      use nix::fcntl::{readlink, readlinkat};
      ostarget = match atdir {
        Some(dir) => {
          let fd = dir.as_raw_fd();
          readlinkat(fd, &path)?
        }
        None => {
          // std::fs::read_link(&path)?.into_os_string()
          readlink(&path)?
        }
      };
    }
    #[cfg(not(unix))]
    {
      let _ = atdir; // avoid unused warning
      ostarget = std::fs::read_link(&path)?.into_os_string();
    }
    let targetstr = ostarget.into_string()?;
    Ok(json!(targetstr.as_str()))
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
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
  nofollow: bool,
  #[allow(unused)]
  atrid: Option<i32>, // FIXME(jp5) truncate
}

fn op_truncate(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: TruncateArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let nofollow = args.nofollow;
  // require len to be 63 bit unsigned
  let len: u64 = args.len.try_into()?;
  let create = args.create;
  let create_new = args.create_new;

  if args.mode.is_some() && !(create || create_new) {
    return Err(OpError::type_error(
      "specified mode without allowing file creation".to_string(),
    ));
  }

  state.check_write(&path)?;
  // require --allow-read to check whether `path` already exists
  if !create || create_new {
    state.check_read(&path)?;
  }

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    debug!("op_truncate {} {} {}", path.display(), len, nofollow);
    let mut open_options = tokio_open_options(args.mode, nofollow);
    open_options
      .create(create)
      .create_new(create_new)
      .write(true);
    let mut file = match open_options.open(&path).await {
      Err(e)
        if cfg!(windows)
          && create_new
          && e.kind() == std::io::ErrorKind::PermissionDenied
          && tokio::fs::metadata(&path)
            .await
            .map_or(false, |m| m.is_dir()) =>
      {
        // alternately, "The file exists. (os error 80)"
        return Err(OpError::already_exists(
          "Cannot create a file when that file already exists. (os error 183)"
            .to_string(),
        ));
      }
      Err(e) => return Err(OpError::from(e)),
      Ok(f) => f,
    };
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
) -> std::io::Result<PathBuf> {
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
      Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
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

  // FIXME(jp2)
  let is_sync = args.promise_id.is_none();
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

  // FIXME(jp2)
  let is_sync = args.promise_id.is_none();
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
  nofollow: bool,
  atrid: Option<i32>,
}

fn op_utime(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  let args: UtimeArgs = serde_json::from_value(args)?;
  let path = resolve_from_cwd(Path::new(&args.path))?;
  let nofollow = args.nofollow;
  // require times to be 63 bit unsigned
  let atime: u64 = args.atime.try_into()?;
  let mtime: u64 = args.mtime.try_into()?;

  state.check_write(&path)?;

  let atdir = match args.atrid {
    Some(atrid) if cfg!(unix) => {
      let state = state.borrow();
      let resource_holder = state
        .resource_table
        .get::<StreamResourceHolder>(atrid as u32)
        .ok_or_else(OpError::bad_resource_id)?;

      let tokio_dir = match resource_holder.resource {
        StreamResource::FsFile(ref file, _) => file,
        _ => return Err(OpError::bad_resource_id()),
      };
      Some(futures::executor::block_on(tokio_dir.try_clone())?)
    }
    Some(_) => return Err(OpError::not_implemented()),
    None => None,
  };

  // FIXME(jp3)
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    debug!(
      "op_utime {} {} {} {}",
      path.display(),
      atime,
      mtime,
      nofollow
    );
    #[cfg(unix)]
    {
      use nix::sys::stat::{utimensat, UtimensatFlags};
      use nix::sys::time::{TimeSpec, TimeValLike};
      let atime = TimeSpec::seconds(atime as i64);
      let mtime = TimeSpec::seconds(mtime as i64);
      let flag = if nofollow {
        UtimensatFlags::NoFollowSymlink
      } else {
        UtimensatFlags::FollowSymlink
      };
      let fd = atdir.map(|dir| dir.as_raw_fd());
      utimensat(fd, &path, &atime, &mtime, flag)?;
    }
    #[cfg(not(unix))]
    {
      use utime::set_file_times;
      let _ = atdir; // avoid unused warning
      set_file_times(&path, atime, mtime)?;
    }
    Ok(json!({}))
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
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

#[cfg(unix)]
fn check_open_for_writing(file: &tokio::fs::File) -> Result<RawFd, OpError> {
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
fn check_open_for_reading(file: &tokio::fs::File) -> Result<RawFd, OpError> {
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
    check_open_for_writing(&file)?;
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
    StreamResource::FsFile(ref file, ref _metadata) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      check_open_for_writing(&file)?;
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

  // FIXME(jp3)
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    #[cfg(unix)]
    {
      use nix::sys::stat::futimens;
      use nix::sys::time::{TimeSpec, TimeValLike};
      let fd = check_open_for_writing(&file)?;
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
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
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
    StreamResource::FsFile(ref file, ref _metadata) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  let is_sync = args.promise_id.is_none();
  let fut = async move {
    #[cfg(unix)]
    {
      check_open_for_reading(&file)?;
      debug!("op_fstat {}", rid);
      let metadata = file.metadata().await?;
      get_stat_json(metadata, None)
    }
    #[cfg(not(unix))]
    {
      let _ = file; // avoid unused warning
      return Err(OpError::not_implemented());
    }
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
struct FChownArgs {
  promise_id: Option<u64>,
  rid: i32,
  uid: Option<u32>,
  gid: Option<u32>,
}

fn op_fchown(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  if cfg!(not(unix)) {
    return Err(OpError::not_implemented());
  }
  let args: FChownArgs = serde_json::from_value(args)?;
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
  let file = futures::executor::block_on(tokio_file.try_clone())?;

  // FIXME(jp3)
  let is_sync = args.promise_id.is_none();
  let blocking = move || {
    #[cfg(unix)]
    {
      use crate::nix_extra::fchown;
      use nix::unistd::{Gid, Uid};
      let fd = check_open_for_writing(&file)?;
      debug!(
        "op_fchown {} {} {}",
        rid,
        args.uid.unwrap_or(0xffff_ffff),
        args.gid.unwrap_or(0xffff_ffff)
      );
      let nix_uid = args.uid.map(Uid::from_raw);
      let nix_gid = args.gid.map(Gid::from_raw);
      fchown(fd, nix_uid, nix_gid)?;
    }
    #[cfg(not(unix))]
    {
      let _ = args.uid; // avoid unused warning
      let _ = args.gid;
      let _ = file;
    }
    Ok(json!({}))
  };

  if is_sync {
    let res = blocking()?;
    Ok(JsonOp::Sync(res))
  } else {
    let fut =
      async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
    Ok(JsonOp::Async(fut.boxed_local()))
  }
}

#[derive(Deserialize)]
struct FChdirArgs {
  rid: i32,
}

fn op_fchdir(
  state: &State,
  args: Value,
  _zero_copy: Option<ZeroCopyBuf>,
) -> Result<JsonOp, OpError> {
  if cfg!(not(unix)) {
    return Err(OpError::not_implemented());
  }
  let args: FChdirArgs = serde_json::from_value(args)?;
  let rid = args.rid as u32;

  let state = state.borrow();
  let resource_holder = state
    .resource_table
    .get::<StreamResourceHolder>(rid)
    .ok_or_else(OpError::bad_resource_id)?;

  let tokio_dir = match resource_holder.resource {
    StreamResource::FsFile(ref file, _) => file,
    _ => return Err(OpError::bad_resource_id()),
  };
  let dir = futures::executor::block_on(tokio_dir.try_clone())?;
  #[cfg(unix)]
  {
    let fd = dir.as_raw_fd();
    nix::unistd::fchdir(fd)?;
  }
  #[cfg(not(unix))]
  {
    let _ = dir;
  }
  Ok(JsonOp::Sync(json!({})))
}

/*
blocking_json(is_sync, move || {
  ...
  Ok(json!({}))
})
*/

/*
let blocking = move || {
  ...
  Ok(json!({}))
};
if is_sync {
  let res = blocking()?;
  Ok(JsonOp::Sync(res))
} else {
  let fut = async move { tokio::task::spawn_blocking(blocking).await.unwrap() };
  Ok(JsonOp::Async(fut.boxed_local()))
}
*/

/*
let fut = async move {
  ...
  Ok(json!({}))
};
if is_sync {
  let buf = futures::executor::block_on(fut)?;
  Ok(JsonOp::Sync(buf))
} else {
  Ok(JsonOp::Async(fut.boxed_local()))
}
*/
