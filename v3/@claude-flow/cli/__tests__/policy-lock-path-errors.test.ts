import { afterEach, expect, it, vi } from 'vitest';
import { closeSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { acquireLock, authorizeMcpTool, autoMigratePolicyStateIfNeeded } from '../src/services/policy-runtime.js';

const fault = vi.hoisted(() => ({
  path: '', openError: undefined as unknown, attempts: 0,
  writeError: false, fd: undefined as number | undefined, closed: false,
}));

vi.mock('node:fs', async (importOriginal) => {
  const fs = await importOriginal<typeof import('node:fs')>();
  return {
    ...fs,
    openSync: ((path, flags, mode) => {
      if (path !== fault.path) return fs.openSync(path, flags, mode);
      fault.attempts++;
      if (fault.openError !== undefined) throw fault.openError;
      const fd = fs.openSync(path, flags, mode);
      if (fault.writeError) fault.fd = fd;
      return fd;
    }) satisfies typeof fs.openSync,
    writeFileSync: ((file, data, options) => {
      if (fault.writeError && file === fault.fd) {
        throw Object.assign(new Error('ownership write failed'), { code: 'EIO' });
      }
      fs.writeFileSync(file, data, options);
    }) satisfies typeof fs.writeFileSync,
    closeSync: ((fd) => {
      fs.closeSync(fd);
      if (fd === fault.fd) fault.closed = true;
    }) satisfies typeof fs.closeSync,
  };
});

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
  Object.assign(fault, { path: '', openError: undefined, writeError: false, fd: undefined, closed: false, attempts: 0 });
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function expectImmediateFailure(lock: string, message: string): Promise<void> {
  const started = Date.now();
  await expect(acquireLock(lock)).rejects.toThrow(message);
  expect(Date.now() - started).toBeLessThan(1_000);
}

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
