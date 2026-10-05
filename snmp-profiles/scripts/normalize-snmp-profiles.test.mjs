import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scriptPath = fileURLToPath(new URL('./normalize-snmp-profiles.mjs', import.meta.url));

test('normalizer preserves every explicit profile state', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'sadapp-snmp-states-'));
  try {
    for (const state of ['enabled', 'experimental', 'disabled']) {
      writeFileSync(path.join(directory, `${state}.json`), JSON.stringify({
        profile_name: `fixture-${state}`,
        description: 'normalizer state fixture',
        state,
      }));
    }

    const result = spawnSync(process.execPath, [scriptPath, directory], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    for (const state of ['enabled', 'experimental', 'disabled']) {
      const profile = JSON.parse(readFileSync(path.join(directory, `${state}.json`), 'utf8'));
      assert.equal(profile.state, state);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('normalizer rejects a profile with missing activation state', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'sadapp-snmp-state-required-'));
  try {
    writeFileSync(path.join(directory, 'missing.json'), JSON.stringify({
      profile_name: 'fixture-missing',
      description: 'state-less fixture',
    }));

    const result = spawnSync(process.execPath, [scriptPath, directory], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must declare state/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});