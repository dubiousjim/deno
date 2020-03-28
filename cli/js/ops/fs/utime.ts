// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

function toSecondsFromEpoch(v: number | Date): number {
  return v instanceof Date ? v.valueOf() / 1000 : v;
}

export function utimeSync(
  path: string | number,
  atime: number | Date,
  mtime: number | Date
): void {
  if (typeof path == "string") {
    sendSync("op_utime", {
      path,
      // TODO(ry) split atime, mtime into [seconds, nanoseconds] tuple
      atime: toSecondsFromEpoch(atime),
      mtime: toSecondsFromEpoch(mtime),
      nofollow: false,
    });
  } else {
    sendSync("op_futime", {
      rid: path,
      atime: toSecondsFromEpoch(atime),
      mtime: toSecondsFromEpoch(mtime),
    });
  }
}

export async function utime(
  path: string | number,
  atime: number | Date,
  mtime: number | Date
): Promise<void> {
  if (typeof path == "string") {
    await sendAsync("op_utime", {
      path,
      // TODO(ry) split atime, mtime into [seconds, nanoseconds] tuple
      atime: toSecondsFromEpoch(atime),
      mtime: toSecondsFromEpoch(mtime),
      nofollow: false,
    });
  } else {
    await sendAsync("op_futime", {
      rid: path,
      atime: toSecondsFromEpoch(atime),
      mtime: toSecondsFromEpoch(mtime),
    });
  }
}
