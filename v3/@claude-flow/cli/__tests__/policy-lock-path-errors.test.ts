/** #4343 backport: filesystem failures are not lock contention. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  chmodSync, closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, symlinkSync, unlinkSync, utimesSync, writeFileSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Match the existing rename-retry tests: inject portable errno failures but
// use real files for every path-type, preservation and ownership assertion.
const fault = vi.hoisted(() => ({
  path: '',
  openError: undefined as unknown,
  statError: undefined as unknown,
  readError: undefined as unknown,
  unlinkError: undefined as unknown,
  vanishOnStat: false,
  writeError: false,
  fd: undefined as number | undefined,
  closed: false,
  attempts: 0,
  unlinks: 0,
  reads: 0,
}));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  const openSync: typeof actual.openSync = (path, flags, mode) => {
    if (String(path) === fault.path) {
      fault.attempts++;
      if (fault.openError !== undefined) throw fault.openError;
      if (typeof flags === 'number' && (flags & actual.constants.O_CREAT) === 0) {
        fault.reads++;
        if (fault.readError !== undefined) throw fault.readError;
      }
    }
    const fd = actual.openSync(path, flags, mode);
    if (String(path) === fault.path && fault.writeError
      && typeof flags === 'number' && (flags & actual.constants.O_WRONLY)) fault.fd = fd;
    return fd;
  };
  const lstatSync = ((path: Parameters<typeof actual.lstatSync>[0], options?: unknown) => {
    if (String(path) === fault.path) {
      if (fault.statError !== undefined) throw fault.statError;
      if (fault.vanishOnStat) {
        fault.vanishOnStat = false;
        actual.unlinkSync(path);
      }
    }
    return actual.lstatSync(path, options as never);
  }) as typeof actual.lstatSync;
  const writeFileSync: typeof actual.writeFileSync = (file, data, options) => {
    if (fault.writeError && file === fault.fd) throw Object.assign(new Error('I/O failure'), { code: 'EIO' });
    return actual.writeFileSync(file, data, options);
  };
  const closeSync: typeof actual.closeSync = (fd) => {
    if (fd === fault.fd) fault.closed = true;
    return actual.closeSync(fd);
  };
  const unlinkSync: typeof actual.unlinkSync = (path) => {
    if (String(path) === fault.path) {
      fault.unlinks++;
      if (fault.unlinkError !== undefined) throw fault.unlinkError;
    }
    return actual.unlinkSync(path);
  };
  return { ...actual, openSync, lstatSync, writeFileSync, closeSync, unlinkSync,
    default: { ...actual, openSync, lstatSync, writeFileSync, closeSync, unlinkSync } };
});

const { acquireLock, authorizeMcpTool, autoMigratePolicyStateIfNeeded } = await import('../src/services/policy-runtime.js');
const roots: string[] = [];

function setup(): { root: string; lock: string } {
  const root = mkdtempSync(join(tmpdir(), 'ruflo-lock-path-'));
  roots.push(root);
  const lock = join(root, 'state.lock');
  fault.path = lock;
  return { root, lock };
}

afterEach(() => {
  if (fault.fd !== undefined && !fault.closed) closeSync(fault.fd);
  Object.assign(fault, { path: '', openError: undefined, statError: undefined,
    readError: undefined, unlinkError: undefined, vanishOnStat: false,
    writeError: false, fd: undefined, closed: false, attempts: 0, unlinks: 0, reads: 0 });
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function expectImmediateFailure(lock: string, message: string): Promise<void> {
  const started = Date.now();
  await expect(acquireLock(lock)).rejects.toThrow(message);
  expect(Date.now() - started).toBeLessThan(1_000);
}

describe('lock creation and inspection errors', () => {
  it.skipIf(process.platform === 'win32')('reports a real filesystem EACCES without waiting', async (context) => {
    const { root, lock } = setup();
    chmodSync(root, 0o500);
    try {
      // Some privileged runners bypass mode bits. Check the OS behavior
      // first so this case never claims to test permissions it did not deny.
      let denied = false;
      try { writeFileSync(join(root, 'permission-probe'), 'probe'); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EACCES') throw error;
        denied = true;
      }
      if (!denied) { context.skip(); return; }
      await expectImmediateFailure(lock, 'policy-state-lock-error: EACCES');
      expect(existsSync(lock)).toBe(false);
    } finally { chmodSync(root, 0o700); }
  });

  it.each(['EACCES', 'EPERM', 'EROFS', 'EIO', 'ENOSPC'])('reports %s immediately without retry or takeover', async (code) => {
    const { lock } = setup();
    fault.openError = Object.assign(new Error('filesystem failure'), { code });
    await expectImmediateFailure(lock, `policy-state-lock-error: ${code}`);
    expect(fault.attempts).toBe(1);
    expect(existsSync(lock)).toBe(false);
    expect(existsSync(`${lock}.reclaim`)).toBe(false);
  });

  it.each([new Error('unclassified failure'), 'unclassified failure'])('keeps an errno-free error diagnostic', async (error) => {
    const { lock } = setup();
    fault.openError = error;
    await expectImmediateFailure(lock, 'policy-state-lock-error: unclassified failure');
    expect(fault.attempts).toBe(1);
  });

  it('recognizes an O_NOFOLLOW ELOOP result as an invalid path', async () => {
    const { lock } = setup();
    fault.openError = Object.assign(new Error('symlink loop'), { code: 'ELOOP' });
    await expectImmediateFailure(lock, 'policy-state-lock-error: lock path is not a regular file');
  });

  it.each(['EACCES', 'EIO'])('does not hide an lstat %s after EEXIST', async (code) => {
    const { lock } = setup();
    writeFileSync(lock, 'preserve this owner');
    fault.statError = Object.assign(new Error('inspection failed'), { code });
    await expectImmediateFailure(lock, `policy-state-lock-error: ${code}`);
    expect(fault.attempts).toBe(1);
    expect(readFileSync(lock, 'utf8')).toBe('preserve this owner');
  });

  it('retries when the owner releases between EEXIST and lstat', async () => {
    const { lock } = setup();
    writeFileSync(lock, 'previous owner');
    fault.vanishOnStat = true;
    const release = await acquireLock(lock);
    expect(JSON.parse(readFileSync(lock, 'utf8')).pid).toBe(process.pid);
    release();
    expect(existsSync(lock)).toBe(false);
  });

  it('reports a missing parent directory as ENOENT', async () => {
    const { root } = setup();
    await expectImmediateFailure(join(root, 'missing', 'state.lock'), 'policy-state-lock-error: ENOENT');
    expect(existsSync(join(root, 'missing'))).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('reports a file used as the parent as ENOTDIR', async () => {
    const { root } = setup();
    const parent = join(root, 'parent');
    writeFileSync(parent, 'keep');
    await expectImmediateFailure(join(parent, 'state.lock'), 'policy-state-lock-error: ENOTDIR');
    expect(readFileSync(parent, 'utf8')).toBe('keep');
  });

  it('closes the descriptor and fails closed if writing lock ownership fails', async () => {
    const { lock } = setup();
    fault.writeError = true;
    await expectImmediateFailure(lock, 'policy-state-lock-error: EIO');
    expect(fault.closed).toBe(true);
    expect(readFileSync(lock, 'utf8')).toBe('');
  });
});

async function deadLock(): Promise<{ root: string; lock: string; content: string }> {
  const { root, lock } = setup();
  const release = await acquireLock(lock);
  const owner = JSON.parse(readFileSync(lock, 'utf8'));
  release();
  const pid = Number(execFileSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' }));
  expect(() => process.kill(pid, 0)).toThrow();
  const content = JSON.stringify({ ...owner, pid });
  writeFileSync(lock, content);
  fault.attempts = fault.unlinks = fault.reads = 0;
  return { root, lock, content };
}

describe('reclamation does not hide filesystem failures', () => {
  it.each(['EACCES', 'EIO'])('reports guard creation %s immediately', async (code) => {
    const { lock, content } = await deadLock();
    fault.path = `${lock}.reclaim`;
    fault.openError = Object.assign(new Error('guard creation failed'), { code });
    await expectImmediateFailure(lock, `policy-state-lock-error: ${code}`);
    expect(fault.attempts).toBe(1);
    expect(existsSync(fault.path)).toBe(false);
    expect(readFileSync(lock, 'utf8')).toBe(content);
  });

  it.each(['EACCES', 'EIO'])('reports existing lock read %s immediately', async (code) => {
    const { lock, content } = await deadLock();
    fault.readError = Object.assign(new Error('owner read failed'), { code });
    await expectImmediateFailure(lock, `policy-state-lock-error: ${code}`);
    expect(fault.reads).toBe(1);
    expect(readFileSync(lock, 'utf8')).toBe(content);
    expect(existsSync(`${lock}.reclaim`)).toBe(false);
  });

  it('reports dead-owner unlink EACCES without deleting the lock', async () => {
    const { lock, content } = await deadLock();
    fault.unlinkError = Object.assign(new Error('unlink failed'), { code: 'EACCES' });
    await expectImmediateFailure(lock, 'policy-state-lock-error: EACCES');
    expect(fault.unlinks).toBe(1);
    expect(readFileSync(lock, 'utf8')).toBe(content);
    expect(existsSync(`${lock}.reclaim`)).toBe(false);
  });

  it('reports guard-write EIO and closes its descriptor', async () => {
    const { lock, content } = await deadLock();
    fault.path = `${lock}.reclaim`;
    fault.writeError = true;
    await expectImmediateFailure(lock, 'policy-state-lock-error: EIO');
    expect(fault.closed).toBe(true);
    expect(readFileSync(lock, 'utf8')).toBe(content);
    // The incomplete guard has unknown ownership and requires inspection.
    expect(readFileSync(fault.path, 'utf8')).toBe('');
  });

  it('reports guard-cleanup EACCES without retrying or hiding the orphan', async () => {
    const { lock } = await deadLock();
    fault.path = `${lock}.reclaim`;
    fault.unlinkError = Object.assign(new Error('guard cleanup failed'), { code: 'EACCES' });
    await expectImmediateFailure(lock, 'policy-state-lock-error: EACCES');
    expect(fault.unlinks).toBe(1);
    expect(existsSync(lock)).toBe(false);
    expect(JSON.parse(readFileSync(fault.path, 'utf8')).pid).toBe(process.pid);
  });

  it('rejects a directory at the guard path without modifying it', async () => {
    const { lock, content } = await deadLock();
    mkdirSync(`${lock}.reclaim`);
    await expectImmediateFailure(lock, 'policy-state-lock-error: lock path is not a regular file');
    expect(lstatSync(`${lock}.reclaim`).isDirectory()).toBe(true);
    expect(readFileSync(lock, 'utf8')).toBe(content);
  });

  it.skipIf(process.platform === 'win32')('preserves a dangling symlink at the guard path', async () => {
    const { root, lock, content } = await deadLock();
    const target = join(root, 'guard-target');
    symlinkSync(target, `${lock}.reclaim`);
    await expectImmediateFailure(lock, 'policy-state-lock-error: lock path is not a regular file');
    expect(lstatSync(`${lock}.reclaim`).isSymbolicLink()).toBe(true);
    expect(existsSync(target)).toBe(false);
    expect(readFileSync(lock, 'utf8')).toBe(content);
  });
});

describe('nonregular lock paths are preserved', () => {
  it('rejects a directory without removing it or its contents', async () => {
    const { lock } = setup();
    mkdirSync(lock);
    writeFileSync(join(lock, 'keep'), 'sentinel');
    await expectImmediateFailure(lock, 'policy-state-lock-error: lock path is not a regular file');
    expect(lstatSync(lock).isDirectory()).toBe(true);
    expect(readFileSync(join(lock, 'keep'), 'utf8')).toBe('sentinel');
  });

  it.skipIf(process.platform === 'win32')('rejects a FIFO without reading or removing it', async () => {
    const { lock } = setup();
    execFileSync('mkfifo', [lock]);
    utimesSync(lock, new Date(0), new Date(0));
    await expectImmediateFailure(lock, 'policy-state-lock-error: lock path is not a regular file');
    expect(lstatSync(lock).isFIFO()).toBe(true);
  });

  it.skipIf(process.platform === 'win32').each(['regular', 'dangling', 'loop'])('rejects a %s symlink without touching the target', async (kind) => {
    const { root, lock } = setup();
    const target = kind === 'loop' ? lock : join(root, 'target');
    if (kind === 'regular') {
      writeFileSync(target, 'sentinel');
      utimesSync(target, new Date(0), new Date(0));
    }
    symlinkSync(target, lock);
    await expectImmediateFailure(lock, 'policy-state-lock-error: lock path is not a regular file');
    expect(lstatSync(lock).isSymbolicLink()).toBe(true);
    if (kind === 'regular') expect(readFileSync(target, 'utf8')).toBe('sentinel');
    if (kind === 'dangling') expect(existsSync(target)).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('does not unlink a symlink substituted before release', async () => {
    const { root, lock } = setup();
    const release = await acquireLock(lock);
    unlinkSync(lock);
    const target = join(root, 'replacement');
    writeFileSync(target, 'sentinel');
    symlinkSync(target, lock);
    release();
    expect(lstatSync(lock).isSymbolicLink()).toBe(true);
    expect(readFileSync(target, 'utf8')).toBe('sentinel');
  });
});

it('fails at the MCP authorization boundary without changing policy state', async () => {
  const { root } = setup();
  mkdirSync(join(root, '.claude-flow'));
  await autoMigratePolicyStateIfNeeded(root);
  const state = join(root, '.claude-flow', 'policy', 'state.json');
  const before = readFileSync(state, 'utf8');
  fault.path = join(root, '.claude-flow', 'policy', 'state.lock');
  fault.openError = Object.assign(new Error('permission denied'), { code: 'EACCES' });
  const started = Date.now();
  await expect(authorizeMcpTool('memory_retrieve', {}, { projectRoot: root }))
    .rejects.toThrow('policy-state-lock-error: EACCES');
  expect(Date.now() - started).toBeLessThan(1_000);
  expect(readFileSync(state, 'utf8')).toBe(before);
});
