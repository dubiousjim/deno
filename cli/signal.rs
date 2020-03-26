// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
use crate::op_error::OpError;
use std::convert::TryFrom;

#[cfg(unix)]
pub fn kill(pid: i32, signo: i32) -> Result<(), OpError> {
  use nix::sys::signal::{kill as unix_kill, Signal};
  use nix::unistd::Pid;
  let sig = Signal::try_from(signo)?;
  unix_kill(Pid::from_raw(pid), Option::Some(sig)).map_err(OpError::from)
}

#[cfg(not(unix))]
pub fn kill(_pid: i32, _signal: i32) -> Result<(), OpError> {
  // NOOP
  // TODO: implement this for windows
  Ok(())
}
