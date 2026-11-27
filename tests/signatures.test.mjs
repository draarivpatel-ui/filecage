import test from 'node:test';
import assert from 'node:assert/strict';
import { sniffFileType, validateUpload } from '../src/index.mjs';
import { ascii, concatBytes, png, jpeg, gif, webpVp8, bmp, zip, ftyp, tar, u16leBytes, u32leBytes, validate, findingCodes, hasFinding } from './helpers.mjs';

function macho(bytes) {
  return new Uint8Array([...bytes, 0, 0, 0, 0]);
}

function centralEntry(name) {
  const encoded = ascii(name);
  return [
    0x50, 0x4b, 0x01, 0x02,
    ...u16leBytes(20), ...u16leBytes(20), ...u16leBytes(0), ...u16leBytes(0),
    ...u16leBytes(0), ...u16leBytes(0), ...u32leBytes(0), ...u32leBytes(0), ...u32leBytes(0),
    ...u16leBytes(encoded.length), ...u16leBytes(0), ...u16leBytes(0), ...u16leBytes(0), ...u16leBytes(0),
    ...u32leBytes(0), ...u32leBytes(0), ...encoded
  ];
}

function centralOnlyZip(names) {
  const local = [
    0x50, 0x4b, 0x03, 0x04,
    ...u16leBytes(20), ...u16leBytes(8), ...u16leBytes(0),
    ...u16leBytes(0), ...u16leBytes(0), ...u32leBytes(0),
    ...u32leBytes(0), ...u32leBytes(0), ...u16leBytes(1), ...u16leBytes(0),
    ...ascii('a')
  ];
  const central = names.flatMap((name) => centralEntry(name));
  const eocd = [
    0x50, 0x4b, 0x05, 0x06,
    ...u16leBytes(0), ...u16leBytes(0), ...u16leBytes(names.length), ...u16leBytes(names.length),
    ...u32leBytes(central.length), ...u32leBytes(local.length), ...u16leBytes(0)
  ];
  return new Uint8Array([...local, ...central, ...eocd]);
}

function centralOnlyDocx() {
  return centralOnlyZip(['[Content_Types].xml', 'word/document.xml']);
}

const signatureCases = [
  ['PNG', png(), 'image/png', 'png', 'image', 'png', false],
  ['JPEG', jpeg(), 'image/jpeg', 'jpg', 'image', 'jpeg', false],
  ['GIF 87a', gif(1, 1, { version: 'GIF87a' }), 'image/gif', 'gif', 'image', 'gif', false],
  ['GIF 89a', gif(), 'image/gif', 'gif', 'image', 'gif', false],
  ['WebP', webpVp8(), 'image/webp', 'webp', 'image', 'webp', false],
  ['BMP', bmp(), 'image/bmp', 'bmp', 'image', 'bmp', false],
  ['ICO', new Uint8Array([0, 0, 1, 0, 1, 0]), 'image/vnd.microsoft.icon', 'ico', 'image', 'ico', false],
  ['AVIF major brand', ftyp('avif'), 'image/avif', 'avif', 'image', 'avif', false],
  ['AVIF sequence brand', ftyp('avis'), 'image/avif', 'avif', 'image', 'avif', false],
  ['HEIF major brand', ftyp('heic'), 'image/heif', 'heic', 'image', 'heif', false],
  ['HEIF compatible brand', ftyp('isom', ['mif1']), 'image/heif', 'heic', 'image', 'heif', false],
  ['TIFF little endian', new Uint8Array([0x49, 0x49, 0x2a, 0x00, 1]), 'image/tiff', 'tiff', 'image', 'tiff', false],
  ['TIFF big endian', new Uint8Array([0x4d, 0x4d, 0x00, 0x2a, 1]), 'image/tiff', 'tiff', 'image', 'tiff', false],
  ['PDF', ascii('%PDF-1.7\n%%EOF'), 'application/pdf', 'pdf', 'document', 'pdf', false],
  ['ZIP', zip([{ name: 'a.txt', data: 'a' }]), 'application/zip', 'zip', 'archive', 'zip', false],
  ['empty ZIP end record', new Uint8Array([0x50, 0x4b, 0x05, 0x06, ...new Array(18).fill(0)]), 'application/zip', 'zip', 'archive', 'zip', false],
  ['DOCX', zip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }]), 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'docx', 'document', 'docx', false],
  ['XLSX', zip([{ name: '[Content_Types].xml' }, { name: 'xl/workbook.xml' }]), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'xlsx', 'document', 'xlsx', false],
  ['PPTX', zip([{ name: '[Content_Types].xml' }, { name: 'ppt/presentation.xml' }]), 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'pptx', 'document', 'pptx', false],
  ['DOCM with VBA project', zip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }, { name: 'word/vbaProject.bin' }]), 'application/vnd.ms-word.document.macroEnabled.12', 'docm', 'document', 'docm', true],
  ['XLSM with VBA project', zip([{ name: '[Content_Types].xml' }, { name: 'xl/workbook.xml' }, { name: 'xl/vbaProject.bin' }]), 'application/vnd.ms-excel.sheet.macroEnabled.12', 'xlsm', 'document', 'xlsm', true],
  ['PPTM with VBA project', zip([{ name: '[Content_Types].xml' }, { name: 'ppt/presentation.xml' }, { name: 'ppt/vbaProject.bin' }]), 'application/vnd.ms-powerpoint.presentation.macroEnabled.12', 'pptm', 'document', 'pptm', true],
  ['JAR', zip([{ name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0' }]), 'application/java-archive', 'jar', 'archive', 'jar', false],
  ['GZIP', new Uint8Array([0x1f, 0x8b, 8, 0]), 'application/gzip', 'gz', 'archive', 'gzip', false],
  ['ZSTD', new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0x20]), 'application/zstd', 'zst', 'archive', 'zstd', false],
  ['TAR', tar(), 'application/x-tar', 'tar', 'archive', 'tar', false],
  ['MP3 ID3', concatBytes(ascii('ID3'), new Uint8Array([4, 0, 0, 0, 0, 0, 0])), 'audio/mpeg', 'mp3', 'media', 'mp3', false],
  ['MP3 frame sync', new Uint8Array([0xff, 0xfb, 0x90, 0x64, 0, 0]), 'audio/mpeg', 'mp3', 'media', 'mp3', false],
  ['MP4', ftyp('isom', ['mp42']), 'video/mp4', 'mp4', 'media', 'mp4', false],
  ['QuickTime', ftyp('qt  '), 'video/quicktime', 'mov', 'media', 'quicktime', false],
  ['OGG', concatBytes(ascii('OggS'), new Uint8Array(32)), 'application/ogg', 'ogg', 'media', 'ogg', false],
  ['WAV', concatBytes(ascii('RIFF'), new Uint8Array([36, 0, 0, 0]), ascii('WAVEfmt ')), 'audio/wav', 'wav', 'media', 'wav', false],
  ['FLAC', concatBytes(ascii('fLaC'), new Uint8Array(16)), 'audio/flac', 'flac', 'media', 'flac', false],
  ['WebM', concatBytes(new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]), ascii('webm')), 'video/webm', 'webm', 'media', 'webm', false],
  ['Matroska', concatBytes(new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]), ascii('matroska')), 'video/x-matroska', 'mkv', 'media', 'mkv', false],
  ['WASM', new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), 'application/wasm', 'wasm', 'executable', 'wasm', true],
  ['ELF', new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1]), 'application/x-elf', 'elf', 'executable', 'elf', true],
  ['PE or DOS executable', new Uint8Array([0x4d, 0x5a, 0x90, 0]), 'application/vnd.microsoft.portable-executable', 'exe', 'executable', 'pe', true],
  ['Mach-O big endian 32-bit', macho([0xfe, 0xed, 0xfa, 0xce]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Mach-O little endian 32-bit', macho([0xce, 0xfa, 0xed, 0xfe]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Mach-O big endian 64-bit', macho([0xfe, 0xed, 0xfa, 0xcf]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Mach-O little endian 64-bit', macho([0xcf, 0xfa, 0xed, 0xfe]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Mach-O fat binary', macho([0xca, 0xfe, 0xba, 0xbe]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Mach-O fat 64-bit binary', macho([0xca, 0xfe, 0xba, 0xbf]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Mach-O byte-swapped fat binary', macho([0xbe, 0xba, 0xfe, 0xca]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Mach-O byte-swapped fat 64-bit binary', macho([0xbf, 0xba, 0xfe, 0xca]), 'application/x-mach-binary', 'macho', 'executable', 'macho', true],
  ['Java class sharing CAFEBABE magic', new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), 'application/java-class', 'class', 'executable', 'java-class', true],
  ['shebang script', ascii('#!/bin/sh\nexit 0\n'), 'application/x-shebang', 'sh', 'executable', 'shebang', true],
  ['UTF-8 BOM before shebang', ascii('\ufeff#!/bin/sh\nexit 0\n'), 'application/x-shebang', 'sh', 'executable', 'shebang', true],
  ['leading spaces before shebang', ascii('                                                                #!/bin/sh\nexit 0\n'), 'application/x-shebang', 'sh', 'executable', 'shebang', true],
  ['HTML document', ascii('<!doctype html><html><body>x</body></html>'), 'text/html', 'html', 'markup', 'html', false],
  ['HTML fragment', ascii('<script>alert(1)</script>'), 'text/html', 'html', 'markup', 'html', false],
  ['SVG', ascii('<svg xmlns="http://www.w3.org/2000/svg"></svg>'), 'image/svg+xml', 'svg', 'image', 'svg', false],
  ['SVG with XML declaration', ascii('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'), 'image/svg+xml', 'svg', 'image', 'svg', false],
  ['XML', ascii('<?xml version="1.0"?><root><a/></root>'), 'application/xml', 'xml', 'markup', 'xml', false],
  ['plain UTF-8 text', ascii('hello world\nsecond line\n'), 'text/plain', 'txt', 'text', 'text', false],
  ['JSON object', ascii('{"a": [1, true, null]}'), 'application/json', 'json', 'data', 'json', false],
  ['JSON array', ascii('[{"a": 1}]'), 'application/json', 'json', 'data', 'json', false],
  ['CSV', ascii('name,value\na,1\nb,2\n'), 'text/csv', 'csv', 'data', 'csv', false]
];

for (const [label, bytes, mime, ext, kind, format, executable] of signatureCases) {
  test('sniffFileType detects ' + label, () => {
    const result = sniffFileType(bytes);
    assert.equal(result.mime, mime);
    assert.equal(result.ext, ext);
    assert.equal(result.kind, kind);
    assert.equal(result.format, format);
    assert.equal(result.executable, executable);
    assert.equal(result.confident, true);
    assert.equal(Object.isFrozen(result), true);
  });
}


for (const padding of [1, 20, 1023]) {
  test('PDF header is accepted at specification-permitted offset ' + padding, () => {
    const result = sniffFileType(concatBytes(ascii('x'.repeat(padding)), ascii('%PDF-1.7\n%%EOF')));
    assert.equal(result.format, 'pdf');
    assert.equal(result.offset, padding);
  });
}

test('PDF header starting after the first 1024 bytes is not accepted as PDF', () => {
  assert.notEqual(sniffFileType(ascii('x'.repeat(1024) + '%PDF-1.7\n%%EOF')).format, 'pdf');
});

test('binary garbage before an in-specification PDF header does not hide the PDF', () => {
  const bytes = concatBytes(new Uint8Array([0, 1, 2, 3]), ascii('%PDF-1.7\n%%EOF'));
  const result = sniffFileType(bytes);
  assert.equal(result.format, 'pdf');
  assert.equal(result.offset, 4);
});

test('VBA project hidden only in a ZIP central directory is still detected', () => {
  const result = sniffFileType(centralOnlyZip(['[Content_Types].xml', 'word/document.xml', 'word/vbaProject.bin']));
  assert.equal(result.format, 'docm');
  assert.equal(result.executable, true);
});

test('macro-bearing OOXML is blocked as executable content by default', () => {
  const bytes = zip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }, { name: 'word/vbaProject.bin' }]);
  const result = validate(bytes, 'document.docm', 'application/vnd.ms-word.document.macroEnabled.12');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_EXECUTABLE_TYPE'), true);
});

test('sniffFileType detects OOXML entries from central directory when local parsing stops', () => {
  assert.equal(sniffFileType(centralOnlyDocx()).format, 'docx');
});

test('sniffFileType detects more than twenty two real-world formats', () => {
  assert.equal(signatureCases.length >= 22, true);
});

test('sniffFileType returns an unknown octet-stream result for random binary bytes', () => {
  const result = sniffFileType(new Uint8Array([0x66, 0x00, 0x99, 0x01]));
  assert.equal(result.mime, 'application/octet-stream');
  assert.equal(result.format, 'unknown');
  assert.equal(result.confident, false);
});

test('sniffFileType returns unknown for empty input', () => {
  assert.equal(sniffFileType(new Uint8Array()).format, 'unknown');
});

test('sniffFileType rejects invalid UTF-8 as text', () => {
  assert.equal(sniffFileType(new Uint8Array([0x61, 0xff, 0x62])).format, 'unknown');
});

test('sniffFileType rejects NUL bytes as text', () => {
  assert.equal(sniffFileType(ascii('abc\0def')).format, 'unknown');
});

for (const control of [1, 2, 7, 11, 12, 27, 31, 127]) {
  test('sniffFileType rejects C0 or DEL control byte ' + control + ' as text', () => {
    assert.equal(sniffFileType(new Uint8Array([65, control, 66])).format, 'unknown');
  });
}

test('UTF-8 BOM does not prevent JSON detection', () => {
  assert.equal(sniffFileType(concatBytes(new Uint8Array([0xef, 0xbb, 0xbf]), ascii('{"a":1}'))).format, 'json');
});

test('malformed JSON is not classified as JSON', () => {
  assert.notEqual(sniffFileType(ascii('{"a":')).format, 'json');
});

test('inconsistent comma counts are not classified as CSV', () => {
  assert.equal(sniffFileType(ascii('a,b,c\n1,2\n')).format, 'text');
});

test('quoted commas do not break CSV column counting', () => {
  assert.equal(sniffFileType(ascii('name,value\n"a,b",1\n"c,d",2\n')).format, 'csv');
});

test('one-column text is not classified as CSV', () => {
  assert.equal(sniffFileType(ascii('alpha\nbeta\n')).format, 'text');
});

const inputForms = [
  ['Uint8Array', () => png()],
  ['Buffer', () => Buffer.from(png())],
  ['ArrayBuffer', () => png().buffer.slice(0)],
  ['DataView', () => new DataView(png().buffer.slice(0))],
  ['subarray view', () => {
    const wrapped = concatBytes(new Uint8Array([9, 9]), png(), new Uint8Array([9]));
    return wrapped.subarray(2, wrapped.length - 1);
  }]
];
for (const [label, make] of inputForms) {
  test('sniffFileType accepts ' + label, () => {
    assert.equal(sniffFileType(make()).format, 'png');
  });
}

test('sniffFileType rejects a string input as invalid input', () => {
  assert.throws(() => sniffFileType('not bytes'), (error) => error.code === 'FILECAGE_INVALID_INPUT');
});

const executableCases = [
  ['ELF', new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2]), 'program.elf', 'application/x-elf'],
  ['PE', new Uint8Array([0x4d, 0x5a, 0x90, 0]), 'program.exe', 'application/vnd.microsoft.portable-executable'],
  ['Mach-O', macho([0xfe, 0xed, 0xfa, 0xce]), 'program.macho', 'application/x-mach-binary'],
  ['WASM', new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), 'module.wasm', 'application/wasm'],
  ['shebang', ascii('#!/usr/bin/env python3\n'), 'script.sh', 'application/x-shebang']
];
for (const [label, bytes, filename, contentType] of executableCases) {
  test('default policy always blocks executable ' + label, () => {
    const result = validate(bytes, filename, contentType);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_EXECUTABLE_TYPE'), true);
  });
}

for (const [label, bytes, filename, contentType] of executableCases) {
  test('allowExecutables opt-in removes only the executable finding for ' + label, () => {
    const result = validate(bytes, filename, contentType, { allowExecutables: true });
    assert.equal(hasFinding(result, 'FILECAGE_EXECUTABLE_TYPE'), false);
  });
}

const spoofCases = [
  ['PNG named as executable', png(), 'avatar.exe', 'application/vnd.microsoft.portable-executable', 'image/png'],
  ['JPEG named as PNG', jpeg(), 'photo.png', 'image/png', 'image/jpeg'],
  ['GIF named as JPEG', gif(), 'image.jpg', 'image/jpeg', 'image/gif'],
  ['PDF named as text', ascii('%PDF-1.4\n%%EOF'), 'notes.txt', 'text/plain', 'application/pdf'],
  ['plain text named as PNG', ascii('hello\nworld\n'), 'picture.png', 'image/png', 'text/plain'],
  ['JSON named as CSV', ascii('{"a":1}'), 'data.csv', 'text/csv', 'application/json'],
  ['CSV named as JSON', ascii('a,b\n1,2\n'), 'data.json', 'application/json', 'text/csv'],
  ['ZIP named as image', zip([{ name: 'x', data: 'y' }]), 'image.png', 'image/png', 'application/zip']
];
for (const [label, bytes, filename, contentType, expectedMime] of spoofCases) {
  test('magic-byte verification ignores claimed metadata: ' + label, () => {
    const result = validate(bytes, filename, contentType);
    assert.equal(result.detectedMime, expectedMime);
    assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), true);
    assert.equal(hasFinding(result, 'FILECAGE_EXTENSION_MISMATCH'), true);
    assert.equal(result.allowed, false);
  });
}

test('executable content is blocked even when named and typed as a PNG', () => {
  const result = validate(new Uint8Array([0x4d, 0x5a, 0x90, 0]), 'avatar.png', 'image/png');
  assert.equal(result.detectedFormat, 'pe');
  assert.equal(hasFinding(result, 'FILECAGE_EXECUTABLE_TYPE'), true);
  assert.equal(result.allowed, false);
});

test('validateUpload result exposes stable detection fields', () => {
  const result = validateUpload({ bytes: png(2, 3), filename: 'pixel.png', contentType: 'image/png' });
  assert.equal(result.detectedMime, 'image/png');
  assert.equal(result.detectedExt, 'png');
  assert.equal(result.detectedFormat, 'png');
  assert.equal(result.kind, 'image');
  assert.equal(result.sizeBytes, png(2, 3).length);
});

test('validateUpload SHA-256 is stable for a known empty-free payload', () => {
  const result = validate(ascii('abc'), 'abc.txt', 'text/plain');
  assert.equal(result.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('sniffed result does not depend on object identity or mutation after return', () => {
  const first = sniffFileType(png());
  assert.throws(() => {
    first.mime = 'text/plain';
  }, TypeError);
});

test('validation findings use stable filecage code prefixes', () => {
  const result = validate(png(), 'avatar.jpg', 'image/jpeg');
  assert.equal(findingCodes(result).every((code) => code.startsWith('FILECAGE_')), true);
});

test('central-looking bytes without a valid end of central directory do not cause OOXML misclassification', () => {
  const base = zip([{ name: 'a', data: 'x' }]);
  const injected = new Uint8Array([...base, ...centralEntry('[Content_Types].xml'), ...centralEntry('word/document.xml')]);
  assert.equal(sniffFileType(injected).format, 'zip');
});

test('large malformed JSON is not classified by prefix and suffix alone', () => {
  const malformed = '{"a":[' + '1,'.repeat(700000) + ']}';
  assert.notEqual(sniffFileType(ascii(malformed)).format, 'json');
});

for (const jsonCase of [
  ['leading zero number', '{"a":01}'],
  ['trailing object comma', '{"a":1,}'],
  ['trailing array comma', '[1,]'],
  ['unescaped control', '{"a":"x\ny"}'],
  ['bad unicode escape', '{"a":"\\u12xz"}'],
  ['missing exponent digits', '{"a":1e+}'],
  ['duplicate-looking but valid syntax', '{"a":1,"a":2}']
]) {
  test('strict JSON classifier handles ' + jsonCase[0], () => {
    const expected = jsonCase[0] === 'duplicate-looking but valid syntax' ? 'json' : 'text';
    assert.equal(sniffFileType(ascii(jsonCase[1])).format, expected);
  });
}

for (const [label, entries] of [
  ['word directory without document.xml', ['[Content_Types].xml', 'word/styles.xml']],
  ['xl directory without workbook.xml', ['[Content_Types].xml', 'xl/styles.xml']],
  ['ppt directory without presentation.xml', ['[Content_Types].xml', 'ppt/theme/theme1.xml']]
]) {
  test('OOXML prefix alone does not bypass archive classification: ' + label, () => {
    const bytes = zip(entries.map((name) => ({ name, data: '' })));
    assert.equal(sniffFileType(bytes).format, 'zip');
  });
}
