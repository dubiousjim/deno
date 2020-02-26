// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

/** Synchronously changes the permission of a specific file/directory of
 * specified path.  Ignores the process's umask.
 *
 *       Deno.chmodSync("/path/to/file", 0o666);
 *
 * Requires `allow-write` permission. */
export function chmodSync(path: string | number, mode: number): void {
  if (typeof path == "string") {
    sendSync("op_chmod", { path, mode });
  } else {
    sendSync("op_fchmod", { rid: path, mode });
  }
}

/** Changes the permission of a specific file/directory of specified path.
 * Ignores the process's umask.
 *
 *       await Deno.chmod("/path/to/file", 0o666);
 *
 * Requires `allow-write` permission. */
export async function chmod(
  path: string | number,
  mode: number
): Promise<void> {
  if (typeof path == "string") {
    await sendAsync("op_chmod", { path, mode });
  } else {
    await sendAsync("op_fchmod", { rid: path, mode });
  }
}
