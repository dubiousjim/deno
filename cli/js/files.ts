// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import {
  EOF,
  Reader,
  Writer,
  Seeker,
  Closer,
  SeekMode,
  SyncReader,
  SyncWriter,
  SyncSeeker
} from "./io.ts";
import { close } from "./ops/resources.ts";
import { read, readSync, write, writeSync } from "./ops/io.ts";
import { seek, seekSync } from "./ops/fs/seek.ts";
export { seek, seekSync } from "./ops/fs/seek.ts";
import {
  open as opOpen,
  openSync as opOpenSync,
  OpenOptions,
  OpenMode
} from "./ops/fs/open.ts";
export { OpenOptions, OpenMode } from "./ops/fs/open.ts";
import { truncate, truncateSync } from "./ops/fs/truncate.ts";
import { chmod, chmodSync } from "./ops/fs/chmod.ts";
import { utime, utimeSync } from "./ops/fs/utime.ts";
import { stat, statSync } from "./ops/fs/stat.ts";
import { FileInfo } from "./file_info.ts";

/** Synchronously open a file and return an instance of the `File` object.
 *
 *       const file = Deno.openSync("/foo/bar.txt", { read: true, write: true });
 *
 * Requires `allow-read` and `allow-write` permissions depending on openMode.
 */
export function openSync(path: string, options?: OpenOptions): File;

/** Synchronously open a file and return an instance of the `File` object.
 *
 *       const file = Deno.openSync("/foo/bar.txt", "r");
 *
 * Requires `allow-read` and `allow-write` permissions depending on openMode.
 */
export function openSync(path: string, openMode?: OpenMode): File;

/**@internal*/
export function openSync(
  path: string,
  modeOrOptions: OpenOptions | OpenMode = "r"
): File {
  let openMode = undefined;
  let options = undefined;

  if (typeof modeOrOptions === "string") {
    openMode = modeOrOptions;
  } else {
    options = checkOpenOptions(modeOrOptions);
  }

  const rid = opOpenSync(path, openMode as OpenMode, options);
  return new File(rid);
}

/** Open a file and resolve to an instance of the `File` object.
 *
 *     const file = await Deno.open("/foo/bar.txt", { read: true, write: true });
 *
 * Requires `allow-read` and `allow-write` permissions depending on openMode.
 */
export async function open(path: string, options?: OpenOptions): Promise<File>;

/** Open a file and resolves to an instance of `Deno.File`.
 *
 *     const file = await Deno.open("/foo/bar.txt, "w+");
 *
 * Requires `allow-read` and `allow-write` permissions depending on openMode.
 */
export async function open(path: string, openMode?: OpenMode): Promise<File>;

/**@internal*/
export async function open(
  path: string,
  modeOrOptions: OpenOptions | OpenMode = "r"
): Promise<File> {
  let openMode = undefined;
  let options = undefined;

  if (typeof modeOrOptions === "string") {
    openMode = modeOrOptions;
  } else {
    options = checkOpenOptions(modeOrOptions);
  }

  const rid = await opOpen(path, openMode as OpenMode, options);
  return new File(rid);
}

/** Creates a file if none exists or truncates an existing file and returns
 *  an instance of `Deno.File`.
 *
 *       const file = Deno.createSync("/foo/bar.txt");
 *
 * Requires `allow-read` and `allow-write` permissions.
 */
export function createSync(path: string): File {
  return openSync(path, "w+");
}

/** Creates a file if none exists or truncates an existing file and resolves to
 *  an instance of `Deno.File`.
 *
 *       const file = await Deno.create("/foo/bar.txt");
 *
 * Requires `allow-read` and `allow-write` permissions.
 */
export function create(path: string): Promise<File> {
  return open(path, "w+");
}

/** The Deno abstraction for reading and writing files. */
export class File
  implements
    Reader,
    SyncReader,
    Writer,
    SyncWriter,
    Seeker,
    SyncSeeker,
    Closer {
  constructor(readonly rid: number) {}

  write(p: Uint8Array): Promise<number> {
    return write(this.rid, p);
  }

  writeSync(p: Uint8Array): number {
    return writeSync(this.rid, p);
  }

  read(p: Uint8Array): Promise<number | EOF> {
    return read(this.rid, p);
  }

  readSync(p: Uint8Array): number | EOF {
    return readSync(this.rid, p);
  }

  seek(offset: number, whence: SeekMode): Promise<number> {
    return seek(this.rid, offset, whence);
  }

  seekSync(offset: number, whence: SeekMode): number {
    return seekSync(this.rid, offset, whence);
  }

  close(): void {
    close(this.rid);
  }

  sync(): void {
    sendSyncJson("op_sync", { rid: this.rid });
  }

  datasync(): void {
    sendSyncJson("op_datasync", { rid: this.rid });
  }

  truncate(len?: number): Promise<void> {
    return truncate(this.rid, len);
  }

  truncateSync(len?: number): void {
    return truncateSync(this.rid, len);
  }

  chmod(mode: number): Promise<void> {
    return chmod(this.rid, mode);
  }

  chmodSync(mode: number): void {
    return chmodSync(this.rid, mode);
  }

  utime(atime: number | Date, mtime: number | Date): Promise<void> {
    return utime(this.rid, atime, mtime);
  }

  utimeSync(atime: number | Date, mtime: number | Date): void {
    return utimeSync(this.rid, atime, mtime);
  }

  stat(): Promise<FileInfo> {
    return stat(this.rid);
  }

  statSync(): FileInfo {
    return statSync(this.rid);
  }
}

/** An instance of `Deno.File` for `stdin`. */
export const stdin = new File(0);
/** An instance of `Deno.File` for `stdout`. */
export const stdout = new File(1);
/** An instance of `Deno.File` for `stderr`. */
export const stderr = new File(2);

/** Check if OpenOptions is set to valid combination of options.
 *  @internal
 */
function checkOpenOptions(options: OpenOptions): OpenOptions {
  if (Object.values(options).filter(val => val === true).length === 0) {
    throw new Error("OpenOptions requires at least one option to be true");
  }

  if (options.truncate && !options.write) {
    throw new Error("'truncate' option requires 'write' option");
  }

  const createOrCreateNew = options.create || options.createNew;

  const writeOrAppend = options.write || options.append;

  if (createOrCreateNew && !writeOrAppend) {
    throw new Error(
      "'create' or 'createNew' options require 'write' or 'append' option"
    );
  }

  if (options.clobber) {
    if (options.createNew) {
      throw new Error("'clobber' option incompatible with 'createNew' option");
    } else if (!writeOrAppend) {
      throw new Error("'clobber' option requires 'write' or 'append' option");
    }
  } else if (options.clobber === false) {
    if (!createOrCreateNew && writeOrAppend) {
      throw new Error(
        "disabling 'clobber', 'create', and 'createNew' options requires read-only access"
      );
    } else if (options.create) {
      if (options.createNew === false) {
        throw new Error(
          "when option 'create' is true, one of options 'clobber' or 'createNew' is implied"
        );
      }
      return { ...options, createNew: true };
    }
  }

  return options;
}
