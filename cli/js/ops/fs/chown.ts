// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export function chownSync(
  path: string | number,
  uid?: number,
  gid?: number
): void {
  if (typeof path == "string") {
    sendSync("op_chown", { path, uid, gid, nofollow: false });
  } else {
    sendSync("op_fchown", { rid: path, uid, gid });
  }
}

export async function chown(
  path: string | number,
  uid?: number,
  gid?: number
): Promise<void> {
  if (typeof path == "string") {
    await sendAsync("op_chown", { path, uid, gid, nofollow: false });
  } else {
    await sendAsync("op_fchown", { rid: path, uid, gid });
  }
}
