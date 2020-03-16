// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
import { unitTest, assert, assertEquals } from "./test_util.ts";

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  function chmodSyncSuccess(): void {
    const enc = new TextEncoder();
    const data = enc.encode("Hello");
    const tempDir = Deno.makeTempDirSync();
    const filename = tempDir + "/test.txt";
    Deno.writeFileSync(filename, data, { mode: 0o666 });

    Deno.chmodSync(filename, 0o777);

    const fileInfo = Deno.statSync(filename);
    assert(fileInfo.mode);
    assertEquals(fileInfo.mode, 0o777);
  }
);

// Check symlink when not on windows
unitTest(
  {
    ignore: Deno.build.os === "win",
    perms: { read: true, write: true }
  },
  function chmodSyncSymlinkSuccess(): void {
    const enc = new TextEncoder();
    const data = enc.encode("Hello");
    const tempDir = Deno.makeTempDirSync();

    const filename = tempDir + "/test.txt";
    Deno.writeFileSync(filename, data, { mode: 0o666 });
    const symlinkName = tempDir + "/test_symlink.txt";
    Deno.symlinkSync(filename, symlinkName);

    let symlinkInfo = Deno.lstatSync(symlinkName);
    assert(symlinkInfo.mode);
    const symlinkMode = symlinkInfo.mode; // platform dependent

    Deno.chmodSync(symlinkName, 0o777);

    // Change actual file mode, not symlink
    const fileInfo = Deno.statSync(filename);
    assert(fileInfo.mode);
    assertEquals(fileInfo.mode, 0o777);
    symlinkInfo = Deno.lstatSync(symlinkName);
    assert(symlinkInfo.mode);
    assertEquals(symlinkInfo.mode, symlinkMode);
  }
);

unitTest({ perms: { write: true } }, function chmodSyncFailure(): void {
  let err;
  try {
    const filename = "/badfile.txt";
    Deno.chmodSync(filename, 0o777);
  } catch (e) {
    err = e;
  }
  assert(err instanceof Deno.errors.NotFound);
});

unitTest({ perms: { write: false } }, function chmodSyncPerm(): void {
  let err;
  try {
    Deno.chmodSync("/somefile.txt", 0o777);
  } catch (e) {
    err = e;
  }
  assert(err instanceof Deno.errors.PermissionDenied);
  assertEquals(err.name, "PermissionDenied");
});

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  async function chmodSuccess(): Promise<void> {
    const enc = new TextEncoder();
    const data = enc.encode("Hello");
    const tempDir = Deno.makeTempDirSync();
    const filename = tempDir + "/test.txt";
    Deno.writeFileSync(filename, data, { mode: 0o666 });

    await Deno.chmod(filename, 0o777);

    const fileInfo = Deno.statSync(filename);
    assert(fileInfo.mode);
    assertEquals(fileInfo.mode, 0o777);
  }
);

// Check symlink when not on windows

unitTest(
  {
    ignore: Deno.build.os === "win",
    perms: { read: true, write: true }
  },
  async function chmodSymlinkSuccess(): Promise<void> {
    const enc = new TextEncoder();
    const data = enc.encode("Hello");
    const tempDir = Deno.makeTempDirSync();

    const filename = tempDir + "/test.txt";
    Deno.writeFileSync(filename, data, { mode: 0o666 });
    const symlinkName = tempDir + "/test_symlink.txt";
    Deno.symlinkSync(filename, symlinkName);

    let symlinkInfo = Deno.lstatSync(symlinkName);
    assert(symlinkInfo.mode);
    const symlinkMode = symlinkInfo.mode; // platform dependent

    await Deno.chmod(symlinkName, 0o777);

    // Just change actual file mode, not symlink
    const fileInfo = Deno.statSync(filename);
    assert(fileInfo.mode);
    assertEquals(fileInfo.mode, 0o777);
    symlinkInfo = Deno.lstatSync(symlinkName);
    assert(symlinkInfo.mode);
    assertEquals(symlinkInfo.mode, symlinkMode);
  }
);

unitTest({ perms: { write: true } }, async function chmodFailure(): Promise<
  void
> {
  let err;
  try {
    const filename = "/badfile.txt";
    await Deno.chmod(filename, 0o777);
  } catch (e) {
    err = e;
  }
  assert(err instanceof Deno.errors.NotFound);
});

unitTest({ perms: { write: false } }, async function chmodPerm(): Promise<
  void
> {
  let err;
  try {
    await Deno.chmod("/somefile.txt", 0o777);
  } catch (e) {
    err = e;
  }
  assert(err instanceof Deno.errors.PermissionDenied);
  assertEquals(err.name, "PermissionDenied");
});

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  function fchmodSyncSuccess(): void {
    const enc = new TextEncoder();
    const data = enc.encode("Hello");
    const tempDir = Deno.makeTempDirSync();
    const filename = tempDir + "/test.txt";
    Deno.writeFileSync(filename, data, { mode: 0o666 });

    const f = Deno.openSync(filename, "r+");
    // On windows no effect, but should not crash
    f.chmodSync(0o777);
    f.close();

    const fileInfo = Deno.statSync(filename);
    assert(fileInfo.mode);
    assertEquals(fileInfo.mode & 0o777, 0o777);
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  async function fchmodSuccess(): Promise<void> {
    const enc = new TextEncoder();
    const data = enc.encode("Hello");
    const tempDir = Deno.makeTempDirSync();
    const filename = tempDir + "/test.txt";
    Deno.writeFileSync(filename, data, { mode: 0o666 });

    const f = await Deno.open(filename, "r+");
    // On windows no effect, but should not crash
    await f.chmod(0o777);
    f.close();

    const fileInfo = Deno.statSync(filename);
    assert(fileInfo.mode);
    assertEquals(fileInfo.mode & 0o777, 0o777);
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: false } },
  function fchmodSyncDenoPermFail(): void {
    let err;
    let caughtError = false;
    const f = Deno.openSync("README.md", "r");
    try {
      f.chmodSync(0o600);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // throw if we lack --write permissions
    assert(caughtError);
    if (caughtError) {
      assert(err instanceof Deno.errors.PermissionDenied);
      assertEquals(err.name, "PermissionDenied");
    }
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: false } },
  async function fchmodDenoPermFail(): Promise<void> {
    let err;
    let caughtError = false;
    const f = await Deno.open("README.md", "r");
    try {
      await f.chmod(0o600);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // throw if we lack --write permissions
    assert(caughtError);
    if (caughtError) {
      assert(err instanceof Deno.errors.PermissionDenied);
      assertEquals(err.name, "PermissionDenied");
    }
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  function fchmodSyncModeFail(): void {
    let err;
    let caughtError = false;
    const filename = Deno.makeTempDirSync() + "/test_chmodSync.txt";
    const f0 = Deno.openSync(filename, "w");
    f0.close();
    const f = Deno.openSync(filename, "r");
    try {
      f.chmodSync(0o600);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // throw if fd is not opened for writing
    assert(caughtError);
    if (caughtError) {
      assert(err instanceof Deno.errors.PermissionDenied);
      assertEquals(err.name, "PermissionDenied");
    }
  }
);

unitTest(
  { ignore: Deno.build.os === "win", perms: { read: true, write: true } },
  async function fchmodModeFail(): Promise<void> {
    let err;
    let caughtError = false;
    const filename = (await Deno.makeTempDir()) + "/test_chmod.txt";
    const f0 = await Deno.open(filename, "w");
    f0.close();
    const f = await Deno.open(filename, "r");
    try {
      await f.chmod(0o600);
    } catch (e) {
      caughtError = true;
      err = e;
    }
    f.close();
    // throw if fd is not opened for writing
    assert(caughtError);
    if (caughtError) {
      assert(err instanceof Deno.errors.PermissionDenied);
      assertEquals(err.name, "PermissionDenied");
    }
  }
);
