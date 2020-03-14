// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export interface RenameOptions {
  /** Defaults to `false`. If set to `true`, no file, directory, or symlink is
   * allowed to exist at the target location. */
  createNew?: boolean;
  /** Sets the option to allow overwriting existing file. Note that setting
   * `{ ..., clobber: false }` has the same effect as
   * `{ ..., createNew: true }`. */
  clobber?: boolean;
}

interface RenameArgs {
  oldpath?: string;
  newpath?: string;
  createNew: boolean;
}

/** Synchronously renames (moves) `oldpath` to `newpath`. If `newpath` already
 * exists and is not a directory, `renameSync()` replaces it. OS-specific
 * restrictions may apply when `oldpath` and `newpath` are in different
 * directories.
 *
 *       Deno.renameSync("old/path", "new/path");
 *
 * Requires `allow-read` and `allow-write` permissions. */
export function renameSync(
  oldpath: string,
  newpath: string,
  options: RenameOptions = {}
): void {
  const args = checkOptions(options);
  args.oldpath = oldpath;
  args.newpath = newpath;
  sendSync("op_rename", args);
}

/** Renames (moves) `oldpath` to `newpath`. If `newpath` already exists and is
 * not a directory, `rename()` replaces it. OS-specific restrictions may apply
 * when `oldpath` and `newpath` are in different directories.
 *
 *       await Deno.rename("old/path", "new/path");
 *
 * Requires `allow-read` and `allow-write`. */
export async function rename(
  oldpath: string,
  newpath: string,
  options: RenameOptions = {}
): Promise<void> {
  const args = checkOptions(options);
  args.oldpath = oldpath;
  args.newpath = newpath;
  await sendAsync("op_rename", args);
}

/** Check we have a valid combination of options.
 *  @internal
 */
function checkOptions(options: RenameOptions): RenameArgs {
  let createNew = options.createNew;
  if (options.clobber) {
    if (createNew) {
      throw new Error("'clobber' option incompatible with 'createNew' option");
    }
  } else if (options.clobber === false) {
    if (createNew === false) {
      throw new Error("one of options 'clobber' or 'createNew' is implied");
    }
    createNew = true;
  }
  return {
    createNew: !!createNew
  };
}
