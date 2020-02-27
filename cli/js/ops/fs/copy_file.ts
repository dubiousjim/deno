// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export interface CopyFileOptions {
  createNew?: boolean;
  clobber?: boolean;
  create?: boolean;
}

interface CopyFileArgs {
  createNew: boolean;
  create: boolean;
  from?: string;
  to?: string;
}

export function copyFileSync(
  fromPath: string,
  toPath: string,
  options: CopyFileOptions = {}
): void {
  const args = checkOptions(options);
  args.from = fromPath;
  args.to = toPath;
  sendSync("op_copy_file", args);
}

export async function copyFile(
  fromPath: string,
  toPath: string,
  options: CopyFileOptions = {}
): Promise<void> {
  const args = checkOptions(options);
  args.from = fromPath;
  args.to = toPath;
  await sendAsync("op_copy_file", args);
}

/** Check we have a valid combination of options.
 *  @internal
 */
function checkOptions(options: CopyFileOptions): CopyFileArgs {
  let createNew = options.createNew;
  const create = options.create;
  if (options.clobber) {
    if (createNew) {
      throw new Error("'clobber' option incompatible with 'createNew' option");
    }
  } else if (options.clobber === false) {
    if (create !== false) {
      if (createNew === false) {
        throw new Error("one of options 'clobber' or 'createNew' is implied");
      }
      createNew = true;
    } else if (!createNew) {
      throw new Error(
        "one of 'clobber', 'create', or 'createNew' options is required"
      );
    }
  }
  return {
    ...options,
    createNew: !!createNew,
    create: createNew || create !== false
  };
}
