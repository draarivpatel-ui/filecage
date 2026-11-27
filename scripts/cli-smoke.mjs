import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'filecage.mjs');
const scratch = mkdtempSync(path.join(tmpdir(), 'filecage-smoke-'));

function pngBytes(width, height) {
  const bytes = [];
  const u32 = (value) => [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
  bytes.push(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
  bytes.push(...u32(13), 0x49, 0x48, 0x44, 0x52, ...u32(width), ...u32(height), 8, 2, 0, 0, 0, 0, 0, 0, 0);
  bytes.push(...u32(0), 0x49, 0x44, 0x41, 0x54, 0, 0, 0, 0);
  bytes.push(...u32(0), 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0);
  return Buffer.from(bytes);
}

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', shell: false });
}

try {
  const safePath = path.join(scratch, 'safe.png');
  const exePath = path.join(scratch, 'payload.png');
  writeFileSync(safePath, pngBytes(8, 8));
  writeFileSync(exePath, Buffer.from([0x4d, 0x5a, 0x90, 0x00]));

  const safe = run(['inspect', safePath, '--allow', 'image/png', '--json']);
  if (safe.status !== 0) throw new Error('safe PNG smoke test failed: ' + safe.stdout + safe.stderr);
  const parsed = JSON.parse(safe.stdout);
  if (parsed.detectedMime !== 'image/png' || parsed.allowed !== true) throw new Error('safe PNG JSON output was incorrect');

  const exe = run(['inspect', exePath, '--json']);
  if (exe.status !== 1) throw new Error('executable disguised as PNG was not rejected with exit 1');

  const missing = run(['inspect', path.join(scratch, 'missing.png')]);
  if (missing.status !== 2) throw new Error('missing file did not produce exit 2');

  console.log('filecage CLI smoke test passed');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
