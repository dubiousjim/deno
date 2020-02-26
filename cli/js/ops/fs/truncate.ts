// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export interface TruncateOptions {
  mode?: number;
}

function coerceLen(len?: number): number {
  if (!len) {
    return 0;
  }

  if (len < 0) {
    return 0;
  }

  return len;
}

export function truncateSync(
  path: string,
  len?: number,
  options: TruncateOptions = {}
): void {
  const args = { path, len: coerceLen(len), mode: options.mode };
  sendSync("op_truncate", args);
}

export async function truncate(
  path: string,
  len?: number,
  options: TruncateOptions = {}
): Promise<void> {
  const args = { path, len: coerceLen(len), mode: options.mode };
  await sendAsync("op_truncate", args);
}
