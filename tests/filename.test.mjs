import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeFilename, assertSafeFilename, validateUpload, FileCageError } from '../src/index.mjs';
import { png } from './helpers.mjs';

function codes(name, options) {
  return sanitizeFilename(name, options).findings.map((item) => item.code);
}

const cleanNames = [
  'photo.png', 'document.pdf', 'data.csv', 'archive.tar.gz', 'name with spaces.jpg',
  'unicode-π-image.webp', 'emoji-🙂-image.gif', 'file.v2-final.png', 'a.jpeg', 'x.txt'
];
for (const name of cleanNames) {
  test('clean filename is preserved: ' + JSON.stringify(name), () => {
    const report = sanitizeFilename(name);
    assert.equal(report.filename, name);
    assert.equal(report.changed, false);
    assert.deepEqual(report.findings, []);
    assert.equal(report.byteLength, Buffer.byteLength(name, 'utf8'));
  });
}

const separatorCases = [
  ['../photo.png', 'photo.png'],
  ['../../photo.png', 'photo.png'],
  ['..\\photo.png', 'photo.png'],
  ['C:\\fakepath\\photo.png', 'photo.png'],
  ['C:/fakepath/photo.png', 'photo.png'],
  ['/tmp/photo.png', 'photo.png'],
  ['//server/share/photo.png', 'photo.png'],
  ['folder/subfolder/photo.png', 'photo.png'],
  ['folder\\subfolder\\photo.png', 'photo.png'],
  ['a/b/c/', 'file'],
  ['../', 'file'],
  ['\\\\server\\share\\', 'file']
];
for (const [input, expected] of separatorCases) {
  test('path separators are stripped from ' + JSON.stringify(input), () => {
    const report = sanitizeFilename(input);
    assert.equal(report.filename, expected);
    assert.equal(report.filename.includes('/'), false);
    assert.equal(report.filename.includes('\\'), false);
    assert.equal(codes(input).includes('FILECAGE_FILENAME_PATH_SEPARATOR'), true);
  });
}

for (const name of ['', '.', '..']) {
  test('empty or relative filename is rejected: ' + JSON.stringify(name), () => {
    const report = sanitizeFilename(name);
    assert.equal(report.filename, 'file');
    assert.equal(report.findings.length > 0, true);
    assert.throws(() => assertSafeFilename(name), (error) => error instanceof FileCageError);
  });
}

test('NUL is reported with its own filename code', () => {
  assert.equal(codes('safe\0name.png').includes('FILECAGE_FILENAME_NUL'), true);
  assert.equal(sanitizeFilename('safe\0name.png').filename, 'safename.png');
});

for (let value = 1; value <= 31; value += 1) {
  test('C0 control U+' + value.toString(16).padStart(4, '0') + ' is rejected and removed', () => {
    const input = 'a' + String.fromCharCode(value) + 'b.png';
    const report = sanitizeFilename(input);
    assert.equal(codes(input).includes('FILECAGE_FILENAME_CONTROL'), true);
    assert.equal(report.filename, 'ab.png');
  });
}

for (let value = 0x80; value <= 0x9f; value += 1) {
  test('C1 control U+' + value.toString(16).padStart(4, '0') + ' is rejected and removed', () => {
    const input = 'a' + String.fromCharCode(value) + 'b.png';
    const report = sanitizeFilename(input);
    assert.equal(codes(input).includes('FILECAGE_FILENAME_CONTROL'), true);
    assert.equal(report.filename, 'ab.png');
  });
}

for (let value = 0x202a; value <= 0x202e; value += 1) {
  test('bidi control U+' + value.toString(16).toUpperCase() + ' is rejected and removed', () => {
    const input = 'a' + String.fromCodePoint(value) + 'b.png';
    assert.equal(codes(input).includes('FILECAGE_FILENAME_BIDI'), true);
    assert.equal(sanitizeFilename(input).filename, 'ab.png');
  });
}

for (let value = 0x2066; value <= 0x2069; value += 1) {
  test('bidi isolate U+' + value.toString(16).toUpperCase() + ' is rejected and removed', () => {
    const input = 'a' + String.fromCodePoint(value) + 'b.png';
    assert.equal(codes(input).includes('FILECAGE_FILENAME_BIDI'), true);
    assert.equal(sanitizeFilename(input).filename, 'ab.png');
  });
}

for (const value of [0x200e, 0x200f]) {
  test('bidi mark U+' + value.toString(16).toUpperCase() + ' is rejected and removed', () => {
    const input = 'a' + String.fromCodePoint(value) + 'b.png';
    assert.equal(codes(input).includes('FILECAGE_FILENAME_BIDI'), true);
    assert.equal(sanitizeFilename(input).filename, 'ab.png');
  });
}

test('RTLO extension spoof report U+202E gnp.exe is detected', () => {
  const input = 'report\u202Egnp.exe';
  const report = sanitizeFilename(input);
  assert.equal(codes(input).includes('FILECAGE_FILENAME_BIDI'), true);
  assert.equal(report.filename, 'reportgnp.exe');
  assert.equal(report.sourceExtension, 'exe');
});

test('RTLO double-extension spoof remains rejected during upload validation by default', () => {
  const result = validateUpload({ bytes: png(), filename: 'invoice\u202Egpj.exe', contentType: 'image/png' });
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.code === 'FILECAGE_FILENAME_BIDI'), true);
});

const reservedBase = ['CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'];
for (const stem of reservedBase) {
  test('Windows reserved device ' + stem + ' is rejected and neutralized', () => {
    const report = sanitizeFilename(stem);
    assert.equal(codes(stem).includes('FILECAGE_FILENAME_RESERVED_DEVICE'), true);
    assert.equal(report.filename.startsWith('file-'), true);
  });
  test('Windows reserved device ' + stem + ' with extension is rejected', () => {
    const input = stem + '.txt';
    assert.equal(codes(input).includes('FILECAGE_FILENAME_RESERVED_DEVICE'), true);
    assert.equal(sanitizeFilename(input).filename.startsWith('file-'), true);
  });
}

for (const prefix of ['COM', 'LPT']) {
  for (let number = 1; number <= 9; number += 1) {
    test('Windows reserved device ' + prefix + number + ' is rejected', () => {
      const input = prefix + number + '.png';
      assert.equal(codes(input).includes('FILECAGE_FILENAME_RESERVED_DEVICE'), true);
      assert.equal(sanitizeFilename(input).filename.startsWith('file-'), true);
    });
  }
}

for (const [input, key] of [
  ['com¹.txt', 'com1'], ['com².txt', 'com2'], ['com³.txt', 'com3'],
  ['lpt¹.txt', 'lpt1'], ['lpt².txt', 'lpt2'], ['lpt³.txt', 'lpt3']
]) {
  test('Unicode superscript reserved device ' + input + ' is rejected as ' + key, () => {
    const report = sanitizeFilename(input);
    assert.equal(report.findings.some((item) => item.code === 'FILECAGE_FILENAME_RESERVED_DEVICE' && item.actual === key), true);
    assert.equal(report.filename.startsWith('file-'), true);
  });
}

test('mixed-case reserved device names are rejected', () => {
  assert.equal(codes('cOm7.PNG').includes('FILECAGE_FILENAME_RESERVED_DEVICE'), true);
});

for (const input of ['name.', 'name..', 'name ', 'name  ', 'name. ', 'name .', 'photo.png.', 'photo.png ']) {
  test('trailing dots or spaces are rejected: ' + JSON.stringify(input), () => {
    const report = sanitizeFilename(input);
    assert.equal(codes(input).includes('FILECAGE_FILENAME_TRAILING_DOTS_SPACES'), true);
    assert.equal(/[. ]$/.test(report.filename), false);
  });
}

const activeFinalExtensions = [
  'exe', 'dll', 'com', 'bat', 'cmd', 'scr', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'mjs',
  'wsf', 'wsh', 'jar', 'php', 'phtml', 'asp', 'aspx', 'jsp', 'html', 'htm', 'svg', 'xml',
  'msi', 'msp', 'lnk', 'reg', 'sh', 'command'
];
for (const extension of activeFinalExtensions) {
  test('double extension ending in .' + extension + ' is detected', () => {
    const input = 'invoice.pdf.' + extension;
    const report = sanitizeFilename(input);
    assert.equal(report.findings.some((item) => item.code === 'FILECAGE_FILENAME_DOUBLE_EXTENSION'), true);
    assert.equal(report.filename.includes('.pdf.'), false);
  });
}

for (const input of ['archive.tar.gz', 'backup.tar.zst', 'photo.jpeg', 'data.json', 'readme.txt', 'file.v2.png', 'a.b.txt']) {
  test('non-active multi-dot filename is not flagged as a double-extension attack: ' + input, () => {
    assert.equal(codes(input).includes('FILECAGE_FILENAME_DOUBLE_EXTENSION'), false);
  });
}

for (const [input, expected] of [
  ['invoice.pdf.exe', 'invoice_pdf.exe'],
  ['avatar.png.php', 'avatar_png.php'],
  ['doc.jpg.html', 'doc_jpg.html']
]) {
  test('double extension is neutralized deterministically: ' + input, () => {
    assert.equal(sanitizeFilename(input).filename, expected);
  });
}

for (const char of ['<', '>', ':', '"', '|', '?', '*']) {
  test('Windows-unsafe character ' + JSON.stringify(char) + ' is replaced', () => {
    const input = 'a' + char + 'b.png';
    const report = sanitizeFilename(input);
    assert.equal(codes(input).includes('FILECAGE_FILENAME_UNSAFE_CHAR'), true);
    assert.equal(report.filename, 'a_b.png');
  });
}

test('Unicode slash lookalikes are replaced rather than treated as safe text', () => {
  const report = sanitizeFilename('a\u2215b.png');
  assert.equal(report.filename, 'a_b.png');
  assert.equal(report.findings.some((item) => item.code === 'FILECAGE_FILENAME_UNSAFE_CHAR'), true);
});

test('filename output never exceeds the 255 byte UTF-8 cap for long ASCII input', () => {
  const input = 'a'.repeat(300) + '.png';
  const report = sanitizeFilename(input);
  assert.equal(report.byteLength <= 255, true);
  assert.equal(report.filename.endsWith('.png'), true);
  assert.equal(report.findings.some((item) => item.code === 'FILECAGE_FILENAME_TOO_LONG'), true);
});

test('long filename truncation is deterministic', () => {
  const input = 'a'.repeat(300) + '.png';
  assert.equal(sanitizeFilename(input).filename, sanitizeFilename(input).filename);
});

test('truncation does not split a multibyte UTF-8 character', () => {
  const input = 'π'.repeat(150) + '.png';
  const report = sanitizeFilename(input);
  assert.equal(report.byteLength <= 255, true);
  assert.equal(Buffer.byteLength(report.filename, 'utf8'), report.byteLength);
  assert.equal(report.filename.endsWith('.png'), true);
});

test('custom byte cap is enforced', () => {
  const report = sanitizeFilename('a'.repeat(100) + '.png', { maxBytes: 32 });
  assert.equal(report.byteLength <= 32, true);
});

test('filename fallback is deterministic for names that sanitize to nothing', () => {
  for (const input of ['\0', '\u202E', '...', '   ', '<>*']) {
    const report = sanitizeFilename(input);
    assert.equal(report.filename.length > 0, true);
    assert.equal(report.filename.includes('\0'), false);
  }
});

test('assertSafeFilename returns the report for a clean name', () => {
  const report = assertSafeFilename('photo.png');
  assert.equal(report.filename, 'photo.png');
});

for (const input of ['../photo.png', 'CON.txt', 'invoice.pdf.exe', 'report\u202Egnp.exe', 'a\0b.png']) {
  test('assertSafeFilename throws for hostile input ' + JSON.stringify(input), () => {
    assert.throws(() => assertSafeFilename(input), (error) => {
      assert.equal(error.name, 'FileCageError');
      assert.equal(typeof error.code, 'string');
      return true;
    });
  });
}

test('validateUpload rejects path traversal filenames by default', () => {
  const result = validateUpload({ bytes: png(), filename: '../photo.png', contentType: 'image/png' });
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.code === 'FILECAGE_FILENAME_PATH_SEPARATOR' && item.severity === 'error'), true);
});

test('filenameAction sanitize downgrades neutralized filename findings to warnings', () => {
  const result = validateUpload({ bytes: png(), filename: '../photo.png', contentType: 'image/png' }, { filenameAction: 'sanitize' });
  assert.equal(result.allowed, true);
  assert.equal(result.safeFilename, 'photo.png');
  assert.equal(result.findings.some((item) => item.code === 'FILECAGE_FILENAME_PATH_SEPARATOR' && item.severity === 'warning'), true);
});

test('filenameAction sanitize does not downgrade content spoofing findings', () => {
  const result = validateUpload({ bytes: png(), filename: 'invoice.pdf.exe', contentType: 'image/png' }, { filenameAction: 'sanitize' });
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.code === 'FILECAGE_EXTENSION_MISMATCH' && item.severity === 'error'), true);
});

test('validateUpload canonicalizes an alias extension to the verified canonical extension', () => {
  const result = validateUpload({ bytes: png(), filename: 'PHOTO.PNG', contentType: 'image/png' });
  assert.equal(result.safeFilename, 'PHOTO.png');
});

test('validateUpload canonicalizes jpeg to jpg after alias verification', () => {
  const { jpeg } = awaitImportHelper();
  const result = validateUpload({ bytes: jpeg(), filename: 'photo.jpeg', contentType: 'image/jpeg' });
  assert.equal(result.allowed, true);
  assert.equal(result.safeFilename, 'photo.jpg');
});

function awaitImportHelper() {
  return { jpeg: (width = 1, height = 1) => new Uint8Array([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x0b, 8, 0, height, 0, width, 1, 1, 0x11, 0, 0xff, 0xd9]) };
}

test('sanitizeFilename report is frozen', () => {
  const report = sanitizeFilename('photo.png');
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.findings), true);
});
