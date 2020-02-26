// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export interface OpenOptions {
  read?: boolean;
  write?: boolean;
  append?: boolean;
  truncate?: boolean;
  create?: boolean;
  createNew?: boolean;
  /** Sets the option to allow overwriting existing file (defaults to `true` when
   * writing). Note that setting `{ ..., clobber: false, create: true }` has the
   * same effect as `{ ..., createNew: true }`. */
  clobber?: boolean;
  /** Permissions to use if creating the file (defaults to `0o666`, before
   * the process's umask).
   * It's an error to specify mode without also setting create or createNew to `true`.
   * Does nothing/raises on Windows. */
  mode?: number;
}

export type OpenMode = "r" | "r+" | "w" | "w+" | "a" | "a+" | "x" | "x+";

export function openSync(
  path: string,
  openMode: OpenMode | undefined,
  options: OpenOptions | undefined
): number {
  const mode: number | undefined = options?.mode;
  return sendSync("op_open", { path, options, openMode, mode });
}

export async function open(
  path: string,
  openMode: OpenMode | undefined,
  options: OpenOptions | undefined
): Promise<number> {
  const mode: number | undefined = options?.mode;
  return await sendAsync("op_open", {
    path,
    options,
    openMode,
    mode
  });
}
