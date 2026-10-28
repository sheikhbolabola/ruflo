import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { coordinationTools } from '../src/mcp-tools/coordination-tools.js';

const originalProjectCwd = process.env.CLAUDE_FLOW_CWD;
const tool = coordinationTools.find(t => t.name === 'coordination_sync')!;
let scratch: string;

const sync = async (input: Record<string, unknown>): Promise<any> => tool.handler(input);

beforeEach(() => {
  scratch = mkdtempSync(join(tmpdir(), 'ruflo-coordination-sync-'));
  process.env.CLAUDE_FLOW_CWD = scratch;
});

afterEach(() => {
  if (originalProjectCwd === undefined) delete process.env.CLAUDE_FLOW_CWD;
  else process.env.CLAUDE_FLOW_CWD = originalProjectCwd;
  rmSync(scratch, { recursive: true, force: true });
});

describe('coordination_sync trigger without a sync backend', () => {
  it('refuses for an empty node collection and does not create a store', async () => {
    const result = await sync({ action: 'trigger', force: true });
    expect(result).toMatchObject({ success: false, action: 'trigger', syncCount: 0 });
    expect(result.error).toMatch(/no sync backend/);
    expect(result).not.toHaveProperty('nodesSync');
    expect(existsSync(join(scratch, '.claude-flow', 'coordination', 'store.json'))).toBe(false);
  });

  it('preserves the stored record and pending changes with registered nodes', async () => {
    const dir = join(scratch, '.claude-flow', 'coordination');
    mkdirSync(dir, { recursive: true });
    const path = join(dir, 'store.json');
    const lastSync = '2026-01-01T00:00:00.000Z';
    const stored = {
      nodes: { one: { id: 'one', status: 'active', load: 0, lastHeartbeat: lastSync } },
      sync: { lastSync, syncCount: 3, conflicts: 2, pendingChanges: 2 },
    };
    writeFileSync(path, JSON.stringify(stored));
    const bytesBefore = readFileSync(path);
    const statusBefore = await sync({ action: 'status' });

    const result = await sync({ action: 'trigger' });
    expect(result).toMatchObject({ success: false, action: 'trigger', syncCount: 3, lastSync });
    expect(result.error).toMatch(/no sync backend/);
    expect(result).not.toHaveProperty('nodesSync');
    expect(readFileSync(path)).toEqual(bytesBefore);
    expect((await sync({ action: 'status' })).sync).toEqual(statusBefore.sync);
  });

  it('keeps status and conflict resolution responses compatible', async () => {
    expect(await sync({ action: 'status' })).toMatchObject({ success: true, status: 'synced' });
    expect(await sync({ action: 'resolve' })).toMatchObject({ success: true, action: 'resolve', message: 'No conflicts to resolve' });

    const dir = join(scratch, '.claude-flow', 'coordination');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'store.json'), JSON.stringify({
      nodes: {}, sync: { lastSync: '2026-01-01T00:00:00.000Z', syncCount: 1, conflicts: 2, pendingChanges: 3 },
    }));
    expect(await sync({ action: 'status' })).toMatchObject({ success: true, status: 'conflicts' });
    expect(await sync({ action: 'resolve', conflictResolution: 'merge' })).toMatchObject({
      success: true, action: 'resolved', strategy: 'merge', conflictsResolved: 2,
    });
    expect(await sync({ action: 'status' })).toMatchObject({
      success: true, status: 'pending', sync: { syncCount: 1, conflicts: 0, pendingChanges: 3 },
    });
  });
});
