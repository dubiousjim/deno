// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { open, openSync, OpenOptions } from "./files.ts";
import { writeAll, writeAllSync } from "./buffer.ts";

export interface WriteFileOptions {
  append?: boolean;
  createNew?: boolean;
  clobber?: boolean;
  create?: boolean;
  mode?: number;
}

export function writeFileSync(
  path: string,
  data: Uint8Array,
  options: WriteFileOptions = {}
): void {
  const openOptions: OpenOptions = checkOptions(options);
  openOptions.write = true;
  openOptions.truncate = !openOptions.append;
  const file = openSync(path, openOptions);
  writeAllSync(file, data);
  file.close();
}

export async function writeFile(
  path: string,
  data: Uint8Array,
  options: WriteFileOptions = {}
): Promise<void> {
  const openOptions: OpenOptions = checkOptions(options);
  openOptions.write = true;
  openOptions.truncate = !openOptions.append;
  const file = await open(path, openOptions);
  await writeAll(file, data);
  file.close();
}

/** Check we have a valid combination of options.
 *  @internal
 */
function checkOptions(options: WriteFileOptions): WriteFileOptions {
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
