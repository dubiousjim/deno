// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { sendSync, sendAsync } from "../dispatch_json.ts";

export interface TruncateOptions {
  createNew?: boolean;
  clobber?: boolean;
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
  options: TruncateOptions = {}
): void {
  const args = checkOptions(options);
  args.path = path;
  args.len = coerceLen(len);
  sendSync("op_truncate", args);
}

export async function truncate(
  path: string,
  len?: number,
  options: TruncateOptions = {}
): Promise<void> {
  const args = checkOptions(options);
  args.path = path;
  args.len = coerceLen(len);
  await sendAsync("op_truncate", args);
}

/** Check we have a valid combination of options.
 *  @internal
 */
function checkOptions(options: TruncateOptions): TruncateArgs {
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
