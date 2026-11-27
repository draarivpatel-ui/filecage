/* Windows-safe test discovery for Node 18 and newer. */
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testsDir = path.join(root, 'tests');
const files = readdirSync(testsDir)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => path.join(testsDir, name));

if (files.length === 0) {
  console.error('no tests/*.test.mjs files found');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], {
  cwd: root,
  stdio: 'inherit',
  shell: false
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
if (result.signal) {
  console.error('test runner terminated by signal ' + result.signal);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
