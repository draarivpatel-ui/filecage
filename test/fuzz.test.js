import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { sanitizeFilename } from '../src/index.mjs';

const propertyOptions = { seed: 20261127, numRuns: 100 };
const stem = fc.stringMatching(/^[a-z][a-z0-9]{0,18}$/);
const extension = fc.constantFrom('png', 'jpg', 'txt', 'pdf', 'csv');

test('generated benign filenames are preserved exactly', () => {
  fc.assert(
    fc.property(stem, extension, (name, ext) => {
      const input = `${name}.${ext}`;
      const report = sanitizeFilename(input);
      assert.equal(report.filename, input);
      assert.equal(report.changed, false);
      assert.deepEqual(report.findings, []);
    }),
    propertyOptions,
  );
});

test('generated traversal prefixes are stripped to a neutral basename', () => {
  const prefix = fc.constantFrom('../', '../../', '..\\', 'C:\\', '/tmp/', 'folder/sub/');
  fc.assert(
    fc.property(prefix, stem, extension, (base, name, ext) => {
      const input = `${base}${name}.${ext}`;
      const report = sanitizeFilename(input);
      assert.equal(report.filename, `${name}.${ext}`);
      assert.equal(report.filename.includes('/'), false);
      assert.equal(report.filename.includes('\\'), false);
      assert.ok(
        report.findings.some((finding) => finding.code === 'FILECAGE_FILENAME_PATH_SEPARATOR'),
        JSON.stringify(report.findings),
      );
    }),
    propertyOptions,
  );
});

test('generated control and bidirectional characters are removed and reported', () => {
  const hostileCharacter = fc.constantFrom('\0', '\u0001', '\u007f', '\u202e', '\u2066');
  fc.assert(
    fc.property(stem, hostileCharacter, extension, (name, character, ext) => {
      const input = `${name}${character}evil.${ext}`;
      const report = sanitizeFilename(input);
      assert.equal(report.filename.includes(character), false);
      assert.equal(report.findings.length > 0, true);
      assert.ok(
        report.findings.some((finding) => (
          finding.code === 'FILECAGE_FILENAME_NUL'
          || finding.code === 'FILECAGE_FILENAME_CONTROL'
          || finding.code === 'FILECAGE_FILENAME_BIDI'
        )),
        JSON.stringify(report.findings),
      );
    }),
    propertyOptions,
  );
});

test('generated Windows reserved device names are neutralized', () => {
  const device = fc.constantFrom('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT9');
  fc.assert(
    fc.property(device, extension, (name, ext) => {
      const input = `${name}.${ext}`;
      const report = sanitizeFilename(input);
      assert.equal(report.filename.startsWith('file-'), true);
      assert.ok(
        report.findings.some((finding) => finding.code === 'FILECAGE_FILENAME_RESERVED_DEVICE'),
        JSON.stringify(report.findings),
      );
    }),
    propertyOptions,
  );
});
