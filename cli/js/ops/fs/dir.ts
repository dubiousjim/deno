// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync } from "../dispatch_json.ts";

export function cwd(): string {
  return sendSync("op_cwd");
}

export function chdir(path: string | number): void {
  if (typeof path == "string") {
    sendSync("op_chdir", { path });
  } else {
    sendSync("op_fchdir", { rid: path });
  }
}
