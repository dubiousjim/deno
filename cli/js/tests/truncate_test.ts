// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { unitTest, assertEquals, assert } from "./test_util.ts";

function readDataSync(name: string): string {
  const data = Deno.readFileSync(name);
  const decoder = new TextDecoder("utf-8");
  const text = decoder.decode(data);
  return text;
}

async function readData(name: string): Promise<string> {
  const data = await Deno.readFile(name);
  const decoder = new TextDecoder("utf-8");
  const text = decoder.decode(data);
  return text;
}

function assertFile(path: string, size?: number, mode?: number): void {
  const info = Deno.lstatSync(path);
  assert(info.isFile());
  if (size !== undefined) {
    assertEquals(info.size, size);
  }
  if (Deno.build.os !== "win" && mode !== undefined) {
    assertEquals(info.mode, mode & ~Deno.umask());
  }
}

unitTest(
  { perms: { read: true, write: true } },
  function truncateSyncSuccess(): void {
    const enc = new TextEncoder();
    const d = enc.encode("Hello");
    const filename = Deno.makeTempDirSync() + "/test_truncateSync.txt";
    Deno.writeFileSync(filename, d);
    Deno.truncateSync(filename, 20);
    let data = readDataSync(filename);
    assertEquals(data.length, 20);
    Deno.truncateSync(filename, 5);
    data = readDataSync(filename);
    assertEquals(data.length, 5);
    Deno.truncateSync(filename, -5);
    data = readDataSync(filename);
    assertEquals(data.length, 0);
    Deno.removeSync(filename);
  }
);

unitTest(
  { perms: { read: true, write: true } },
  async function truncateSuccess(): Promise<void> {
    const enc = new TextEncoder();
    const d = enc.encode("Hello");
    const filename = Deno.makeTempDirSync() + "/test_truncate.txt";
    await Deno.writeFile(filename, d);
    await Deno.truncate(filename, 20);
    let data = await readData(filename);
    assertEquals(data.length, 20);
    await Deno.truncate(filename, 5);
    data = await readData(filename);
    assertEquals(data.length, 5);
    await Deno.truncate(filename, -5);
    data = await readData(filename);
    assertEquals(data.length, 0);
    await Deno.remove(filename);
  }
);

unitTest(
  {
    perms: { read: true, write: true }
  },
  function truncateSyncMode(): void {
    const path = Deno.makeTempDirSync() + "/test_truncateSync.txt";
    Deno.truncateSync(path, 20, { mode: 0o626 });
    assertFile(path, 20, 0o626);
  }
);

unitTest(
  {
    perms: { read: true, write: true }
  },
  async function truncateMode(): Promise<void> {
    const path = (await Deno.makeTempDir()) + "/test_truncate.txt";
    await Deno.truncate(path, 20, { mode: 0o626 });
    assertFile(path, 20, 0o626);
  }
);

unitTest({ perms: { write: false } }, function truncateSyncPerm(): void {
  let err;
  try {
    Deno.mkdirSync("/test_truncateSyncPermission.txt");
  } catch (e) {
    err = e;
  }
  assert(err instanceof Deno.errors.PermissionDenied);
  assertEquals(err.name, "PermissionDenied");
});

unitTest({ perms: { write: false } }, async function truncatePerm(): Promise<
  void
> {
  let err;
  try {
    await Deno.mkdir("/test_truncatePermission.txt");
  } catch (e) {
    err = e;
  }
  assert(err instanceof Deno.errors.PermissionDenied);
  assertEquals(err.name, "PermissionDenied");
});

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  function ftruncateSyncSuccess(): void {
    const enc = new TextEncoder();
    const d = enc.encode("Hello");
    const filename = Deno.makeTempDirSync() + "/test_truncateSync.txt";
    Deno.writeFileSync(filename, d);
    const f1 = Deno.openSync(filename, "r+");
    f1.truncateSync(20);
    f1.close();
    let data = readDataSync(filename);
    assertEquals(data.length, 20);
    const f2 = Deno.openSync(filename, "r+");
    f2.truncateSync(5);
    f2.close();
    data = readDataSync(filename);
    assertEquals(data.length, 5);
    const f3 = Deno.openSync(filename, "r+");
    f3.truncateSync(-5);
    f3.close();
    data = readDataSync(filename);
    assertEquals(data.length, 0);
    Deno.removeSync(filename);
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  async function ftruncateSuccess(): Promise<void> {
    const enc = new TextEncoder();
    const d = enc.encode("Hello");
    const filename = Deno.makeTempDirSync() + "/test_truncate.txt";
    await Deno.writeFile(filename, d);
    const f1 = await Deno.open(filename, "r+");
    await f1.truncate(20);
    f1.close();
    let data = await readData(filename);
    assertEquals(data.length, 20);
    const f2 = await Deno.open(filename, "r+");
    await f2.truncate(5);
    f2.close();
    data = await readData(filename);
    assertEquals(data.length, 5);
    const f3 = await Deno.open(filename, "r+");
    await f3.truncate(-5);
    f3.close();
    data = await readData(filename);
    assertEquals(data.length, 0);
    await Deno.remove(filename);
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: false } },
  function ftruncateSyncPerm(): void {
    let err;
    let caughtError = false;
    const f = Deno.openSync("README.md", "r");
    try {
      f.truncateSync(0);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // throw if we lack --write permissions
    assert(caughtError);
    assert(err instanceof Deno.errors.PermissionDenied);
    assertEquals(err.name, "PermissionDenied");
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: false } },
  async function ftruncatePerm(): Promise<void> {
    let err;
    let caughtError = false;
    const f = await Deno.open("README.md", "r");
    try {
      await f.truncate(0);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // throw if we lack --write permissions
    assert(caughtError);
    assert(err instanceof Deno.errors.PermissionDenied);
    assertEquals(err.name, "PermissionDenied");
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  function ftruncateSyncPerm2(): void {
    let err;
    let caughtError = false;
    const filename = Deno.makeTempDirSync() + "/test_truncateSync.txt";
    const f0 = Deno.openSync(filename, "w");
    f0.close();
    const f = Deno.openSync(filename, "r");
    try {
      f.truncateSync(0);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // fd is not opened for writing
    assert(caughtError);
    assert(err instanceof Deno.errors.PermissionDenied);
    assertEquals(err.name, "PermissionDenied");
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  async function ftruncatePerm2(): Promise<void> {
    let err;
    let caughtError = false;
    const filename = (await Deno.makeTempDir()) + "/test_truncate.txt";
    const f0 = await Deno.open(filename, "w");
    f0.close();
    const f = await Deno.open(filename, "r");
    try {
      await f.truncate(0);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // fd is not opened for writing
    assert(caughtError);
    assert(err instanceof Deno.errors.PermissionDenied);
    assertEquals(err.name, "PermissionDenied");
  }
);

unitTest(
  { perms: { read: true, write: true } },
  function truncateSyncCreate(): void {
    const filename = Deno.makeTempDirSync() + "/test.txt";
    let caughtError = false;
    // if create turned off, the file won't be created
    try {
      Deno.truncateSync(filename, 0, { create: false });
    } catch (e) {
      caughtError = true;
      assert(e instanceof Deno.errors.NotFound);
    }
    assert(caughtError);

    // Turn on create, should have no error
    Deno.truncateSync(filename, 10, { create: true });
    assertFile(filename, 10);
    Deno.truncateSync(filename, 0, { create: false });
    assertFile(filename, 0);
  }
);

unitTest(
  { perms: { read: true, write: true } },
  async function truncateCreate(): Promise<void> {
    const filename = Deno.makeTempDirSync() + "/test.txt";
    let caughtError = false;
    // if create turned off, the file won't be created
    try {
      await Deno.truncate(filename, 0, { create: false });
    } catch (e) {
      caughtError = true;
      assert(e instanceof Deno.errors.NotFound);
    }
    assert(caughtError);

    // Turn on create, should have no error
    await Deno.truncate(filename, 10, { create: true });
    assertFile(filename, 10);
    await Deno.truncate(filename, 0, { create: false });
    assertFile(filename, 0);
  }
);

unitTest(
  { perms: { read: true, write: true } },
  function truncateSyncCreateNew(): void {
    const filename = Deno.makeTempDirSync() + "/test.txt";
    // file newly created
    Deno.truncateSync(filename, 0, { createNew: true });
    // createNew: true but file exists
    let caughtError = false;
    try {
      Deno.truncateSync(filename, 0, { createNew: true });
    } catch (e) {
      caughtError = true;
      assert(e instanceof Deno.errors.AlreadyExists);
    }
    assert(caughtError);
    // createNew: false and file exists
    Deno.truncateSync(filename, 10, { createNew: false });
    assertFile(filename, 10);
  }
);

unitTest(
  { perms: { read: true, write: true } },
  async function truncateCreateNew(): Promise<void> {
    const filename = Deno.makeTempDirSync() + "/test.txt";
    // file newly created
    await Deno.truncate(filename, 0, { createNew: true });
    // createNew: true but file exists
    let caughtError = false;
    try {
      await Deno.truncate(filename, 0, { createNew: true });
    } catch (e) {
      caughtError = true;
      assert(e instanceof Deno.errors.AlreadyExists);
    }
    assert(caughtError);
    // createNew: false and file exists
    await Deno.truncate(filename, 10, { createNew: false });
    assertFile(filename, 10);
  }
);

unitTest(
  { perms: { read: true, write: true } },
  function truncateSyncDir(): void {
    const testDir = Deno.makeTempDirSync();
    const dir = testDir + "/dir";
    Deno.mkdirSync(dir);
    let caughtError = false;
    try {
      Deno.truncateSync(dir, 0);
    } catch (e) {
      caughtError = true;
      if (Deno.build.os == "win") {
        assert(e instanceof Deno.errors.PermissionDenied);
      } else {
        assert(e.message.includes("Is a directory"));
      }
    }
    assert(caughtError);
    caughtError = false;
    try {
      Deno.truncateSync(dir, 0, { createNew: true });
    } catch (e) {
      caughtError = true;
      assert(e instanceof Deno.errors.AlreadyExists);
    }
    assert(caughtError);
  }
);

unitTest(
  { perms: { read: true, write: true } },
  async function truncateDir(): Promise<void> {
    const testDir = Deno.makeTempDirSync();
    const dir = testDir + "/dir";
    Deno.mkdirSync(dir);
    let caughtError = false;
    try {
      await Deno.truncate(dir, 0);
    } catch (e) {
      caughtError = true;
      if (Deno.build.os == "win") {
        assert(e instanceof Deno.errors.PermissionDenied);
      } else {
        assert(e.message.includes("Is a directory"));
      }
    }
    assert(caughtError);
    caughtError = false;
    try {
      await Deno.truncate(dir, 0, { createNew: true });
    } catch (e) {
      caughtError = true;
      assert(e instanceof Deno.errors.AlreadyExists);
    }
    assert(caughtError);
  }
);
