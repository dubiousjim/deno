// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync } from "../dispatch_json.ts";

export function sync(rid: number): void {
  sendSync("op_sync", { rid });
}

export function datasync(rid: number): void {
  sendSync("op_datasync", { rid });
}
