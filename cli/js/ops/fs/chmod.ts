// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export function chmodSync(path: string | number, mode: number): void {
  if (typeof path == "string") {
    sendSync("op_chmod", { path, mode, nofollow: false });
  } else {
    sendSync("op_fchmod", { rid: path, mode });
  }
}

export async function chmod(
  path: string | number,
  mode: number
): Promise<void> {
  if (typeof path == "string") {
    await sendAsync("op_chmod", { path, mode, nofollow: false });
  } else {
    await sendAsync("op_fchmod", { rid: path, mode });
  }
}
