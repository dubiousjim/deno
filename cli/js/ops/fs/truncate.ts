// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export interface TruncateOptions {
  createNew?: boolean;
  create?: boolean;
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

interface TruncateArgs {
  createNew: boolean;
  create: boolean;
  mode?: number;
  path?: string;
  len?: number;
}

export function truncateSync(
  path: string,
  len?: number,
  options?: TruncateOptions
): void;

export function truncateSync(rid: number, len?: number): void;

export function truncateSync(
  path: string | number,
  len?: number,
  options: TruncateOptions = {}
): void {
  if (typeof path == "string") {
    const args = checkOptions(options);
    args.path = path;
    args.len = coerceLen(len);
    sendSync("op_truncate", args);
  } else {
    // for the ftruncate variant, we ignore the create option
    const args = { rid: path, len: coerceLen(len), mode: options.mode };
    sendSync("op_ftruncate", args);
  }
}

export function truncate(
  path: string,
  len?: number,
  options?: TruncateOptions
): Promise<void>;

export function truncate(rid: number, len?: number): Promise<void>;

export async function truncate(
  path: string | number,
  len?: number,
  options: TruncateOptions = {}
): Promise<void> {
  if (typeof path == "string") {
    const args = checkOptions(options);
    args.path = path;
    args.len = coerceLen(len);
    await sendAsync("op_truncate", args);
  } else {
    // for the ftruncate variant, we ignore the create option
    const args = { rid: path, len: coerceLen(len), mode: options.mode };
    await sendAsync("op_ftruncate", args);
  }
}

/** Check we have a valid combination of options.
 *  @internal
 */
function checkOptions(options: TruncateOptions): TruncateArgs {
  const createNew = options.createNew;
  const create = options.create;
  return {
    ...options,
    createNew: !!createNew,
    create: createNew || create !== false
  };
}
