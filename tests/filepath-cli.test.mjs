import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, rmSync, existsSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateFilePath, createUploadGuard } from '../src/index.mjs';
import { png, jpeg, hasFinding } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'filecage.mjs');

function scratch() {
  return mkdtempSync(path.join(tmpdir(), 'filecage-test-'));
}

function cleanup(directory) {
  rmSync(directory, { recursive: true, force: true });
}

function writeScratch(directory, name, bytes) {
  const target = path.join(directory, name);
  writeFileSync(target, bytes);
  return target;
}

test('validateFilePath accepts a regular safe PNG', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png(2, 2));
    const result = validateFilePath(target, 'images-safe');
    assert.equal(result.allowed, true, JSON.stringify(result.findings));
    assert.equal(result.detectedMime, 'image/png');
    assert.equal(result.dimensions.width, 2);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath computes the same SHA-256 as buffer validation', () => {
  const dir = scratch();
  try {
    const bytes = png(3, 3);
    const target = writeScratch(dir, 'photo.png', bytes);
    const result = validateFilePath(target);
    assert.match(result.sha256, /^[a-f0-9]{64}$/);
    assert.equal(result.sizeBytes, bytes.length);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects executable bytes inside a regular file', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', new Uint8Array([0x4d, 0x5a, 0x90, 0]));
    const result = validateFilePath(target);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_EXECUTABLE_TYPE'), true);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects filename extension spoofing after reading', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.gif', jpeg());
    const result = validateFilePath(target);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_EXTENSION_MISMATCH'), true);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects an oversized regular file before a bounded read', () => {
  const dir = scratch();
  try {
    const bytes = png();
    const target = writeScratch(dir, 'photo.png', bytes);
    const result = validateFilePath(target, { maxBytes: bytes.length - 1 });
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_PATH_TOO_LARGE'), true);
    assert.equal(hasFinding(result, 'FILECAGE_MAX_BYTES'), true);
    assert.equal(result.sha256, null);
    assert.equal(result.sizeBytes, bytes.length);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects a directory as non-regular', () => {
  const dir = scratch();
  try {
    const nested = path.join(dir, 'nested.png');
    mkdirSync(nested);
    const result = validateFilePath(nested);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_PATH_NOT_REGULAR'), true);
    assert.equal(result.sha256, null);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects a missing file as an I/O failure', () => {
  const dir = scratch();
  try {
    const result = validateFilePath(path.join(dir, 'missing.png'));
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_PATH_IO_ERROR'), true);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects a path containing NUL without touching the filesystem', () => {
  const result = validateFilePath('abc\0def.png');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_PATH_UNSAFE'), true);
});

test('validateFilePath does not leak the inspected path into findings', () => {
  const dir = scratch();
  try {
    const target = path.join(dir, 'missing.png');
    const result = validateFilePath(target);
    assert.equal(JSON.stringify(result.findings).includes(target), false);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects symbolic links', { skip: process.platform === 'win32' }, () => {
  const dir = scratch();
  try {
    const real = writeScratch(dir, 'real.png', png());
    const link = path.join(dir, 'link.png');
    symlinkSync(real, link);
    const result = validateFilePath(link);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_PATH_SYMLINK'), true);
    assert.equal(result.sha256, null);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects FIFOs without blocking on open', { skip: process.platform === 'win32' }, () => {
  const dir = scratch();
  try {
    const fifo = path.join(dir, 'pipe.png');
    const made = spawnSync('mkfifo', [fifo], { shell: false });
    assert.equal(made.status, 0);
    const started = Date.now();
    const result = validateFilePath(fifo);
    assert.equal(Date.now() - started < 2000, true);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_PATH_NOT_REGULAR'), true);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath rejects a character device as non-regular', { skip: process.platform !== 'darwin' && process.platform !== 'linux' }, () => {
  const result = validateFilePath('/dev/null');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_PATH_NOT_REGULAR'), true);
});

for (const badPath of ['', null, 4, {}]) {
  test('validateFilePath rejects invalid path input shape', () => {
    assert.throws(() => validateFilePath(badPath), (error) => error.code === 'FILECAGE_INVALID_INPUT');
  });
}

test('guard validateFilePath uses the guard preset and per-call overrides', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png());
    const guard = createUploadGuard('images-safe');
    assert.equal(guard.validateFilePath(target).allowed, true);
    assert.equal(guard.validateFilePath(target, { maxBytes: 1 }).allowed, false);
  } finally {
    cleanup(dir);
  }
});

function runCli(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', shell: false });
}

test('CLI inspect exits 0 for a safe PNG and emits valid JSON', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png(4, 4));
    const result = runCli(['inspect', target, '--json']);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.allowed, true);
    assert.equal(parsed.detectedMime, 'image/png');
  } finally {
    cleanup(dir);
  }
});

test('CLI --allow accepts an explicitly allowed MIME type', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png());
    const result = runCli(['inspect', target, '--allow', 'image/png']);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  } finally {
    cleanup(dir);
  }
});

test('CLI --allow rejects a verified type outside the list', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png());
    const result = runCli(['inspect', target, '--allow', 'image/jpeg']);
    assert.equal(result.status, 1);
  } finally {
    cleanup(dir);
  }
});

test('CLI exits 1 for an executable disguised as an image', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', new Uint8Array([0x4d, 0x5a, 0x90, 0]));
    const result = runCli(['inspect', target]);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /FILECAGE_EXECUTABLE_TYPE/);
  } finally {
    cleanup(dir);
  }
});

test('CLI exits 1 when max-pixels is exceeded', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png(10, 10));
    const result = runCli(['inspect', target, '--max-pixels', '99']);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /FILECAGE_MAX_PIXELS/);
  } finally {
    cleanup(dir);
  }
});

test('CLI exits 0 when max-pixels is exactly met', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png(10, 10));
    const result = runCli(['inspect', target, '--max-pixels', '100']);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  } finally {
    cleanup(dir);
  }
});

test('CLI exits 1 when max-bytes is exceeded', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png());
    const result = runCli(['inspect', target, '--max-bytes', '2']);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /FILECAGE_PATH_TOO_LARGE|FILECAGE_MAX_BYTES/);
  } finally {
    cleanup(dir);
  }
});

test('CLI exits 2 for a missing file', () => {
  const dir = scratch();
  try {
    const result = runCli(['inspect', path.join(dir, 'missing.png')]);
    assert.equal(result.status, 2);
  } finally {
    cleanup(dir);
  }
});

for (const args of [[], ['inspect'], ['inspect', 'a.png', 'b.png'], ['inspect', 'a.png', '--unknown'], ['inspect', 'a.png', '--max-bytes', 'x'], ['scan', 'a.png']]) {
  test('CLI exits 2 for invalid usage: ' + args.join(' '), () => {
    const result = runCli(args);
    assert.equal(result.status, 2);
  });
}

test('CLI help exits 0 and documents exit codes', () => {
  const result = runCli(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Exit codes/);
  assert.match(result.stdout, /filecage inspect/);
});

test('CLI version exits 0 and prints 1.0.0', () => {
  const result = runCli(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), '1.0.0');
});

test('CLI human output does not contain raw terminal control characters', { skip: process.platform === 'win32' }, () => {
  const dir = scratch();
  try {
    const name = 'bad\u001b[31m.png';
    const target = writeScratch(dir, name, png());
    const result = runCli(['inspect', target]);
    assert.equal(result.stdout.includes('\u001b'), false);
  } finally {
    cleanup(dir);
  }
});

test('CLI JSON output can be parsed and contains stable finding codes', () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', new Uint8Array([0x4d, 0x5a, 0x90, 0]));
    const result = runCli(['inspect', target, '--json']);
    assert.equal(result.status, 1);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.findings.some((item) => item.code === 'FILECAGE_EXECUTABLE_TYPE'), true);
  } finally {
    cleanup(dir);
  }
});


test('validateFilePath rejects executable permission bits on POSIX', { skip: process.platform === 'win32' }, () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png());
    chmodSync(target, 0o755);
    const result = validateFilePath(target, 'images-safe');
    assert.equal(result.allowed, false);
    assert.equal(result.findings.some((item) => item.code === 'FILECAGE_EXECUTABLE_TYPE' && item.actual === 'executable-mode'), true);
  } finally {
    cleanup(dir);
  }
});

test('validateFilePath executable-mode rejection requires explicit executable opt-in', { skip: process.platform === 'win32' }, () => {
  const dir = scratch();
  try {
    const target = writeScratch(dir, 'photo.png', png());
    chmodSync(target, 0o755);
    const result = validateFilePath(target, { preset: 'images-safe', allowExecutables: true });
    assert.equal(result.allowed, true, JSON.stringify(result.findings));
  } finally {
    cleanup(dir);
  }
});

test('CLI error output strips terminal bidi controls', () => {
  const result = runCli(['inspect', 'a.png', '--bad\u202eoption']);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes('\u202e'), false);
});
