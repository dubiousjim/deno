// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";
import { FileInfo, FileInfoImpl } from "../../file_info.ts";

/** @internal */
export interface StatResponse {
  isFile: boolean;
  isDir: boolean;
  isSymlink: boolean;
  size: number;
  modified: number;
  accessed: number;
  created: number;
  name: string | null;
  // Unix only members
  ctime: number;
  dev: number;
  ino: number;
  mode: number;
  nlink: number;
  uid: number;
  gid: number;
  rdev: number;
  blksize: number;
  blocks: number;
}

/** Resolves to a `Deno.FileInfo` for the specified `path`. If `path` is a
 * symlink, information for the symlink will be returned.
 *
 *       const fileInfo = await Deno.lstat("hello.txt");
 *       assert(fileInfo.isFile());
 *
 * Requires `allow-read` permission. */
export async function lstat(path: string): Promise<FileInfo> {
  const res = (await sendAsync("op_stat", {
    path,
    lstat: true
  })) as StatResponse;
  return new FileInfoImpl(res);
}

/** Synchronously returns a `Deno.FileInfo` for the specified `path`. If
 * `path` is a symlink, information for the symlink will be returned.
 *
 *       const fileInfo = Deno.lstatSync("hello.txt");
 *       assert(fileInfo.isFile());
 *
 * Requires `allow-read` permission. */
export function lstatSync(path: string): FileInfo {
  const res = sendSync("op_stat", {
    path,
    lstat: true
  }) as StatResponse;
  return new FileInfoImpl(res);
}

/** Resolves to a `Deno.FileInfo` for the specified `path`. Will always
 * follow symlinks.
 *
 *       const fileInfo = await Deno.stat("hello.txt");
 *       assert(fileInfo.isFile());
 *
 * Requires `allow-read` permission. */
export async function stat(path: string | number): Promise<FileInfo> {
  if (typeof path == "string") {
    const res = (await sendAsync("op_stat", {
      path,
      lstat: false
    })) as StatResponse;
    return new FileInfoImpl(res);
  } else {
    const res = (await sendAsync("op_fstat", {
      rid: path
    })) as StatResponse;
    return new FileInfoImpl(res);
  }
}

/** Synchronously returns a `Deno.FileInfo` for the specified `path`. Will
 * always follow symlinks.
 *
 *       const fileInfo = Deno.statSync("hello.txt");
 *       assert(fileInfo.isFile());
 *
 * Requires `allow-read` permission. */
export function statSync(path: string | number): FileInfo {
  if (typeof path == "string") {
    const res = sendSync("op_stat", {
      path,
      lstat: false
    }) as StatResponse;
    return new FileInfoImpl(res);
  } else {
    const res = sendSync("op_fstat", {
      rid: path
    }) as StatResponse;
    return new FileInfoImpl(res);
  }
}
