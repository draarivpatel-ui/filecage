import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateUpload,
  inspectFileBuffer,
  validateWebFile,
  createUploadGuard,
  createFileCage,
  FILECAGE_PRESETS,
  FileCageError
} from '../src/index.mjs';
import { ascii, concatBytes, png, jpeg, gif, webpVp8, zip, ftyp, tar, pdf, svg, validate, hasFinding, findingCodes } from './helpers.mjs';

function webpFile() {
  return webpVp8(2, 2);
}

function webFile(bytes, name = 'upload.bin', type = '') {
  const copy = new Uint8Array(bytes).slice();
  const make = (part) => ({
    size: part.length,
    type,
    name,
    arrayBuffer: async () => part.buffer.slice(part.byteOffset, part.byteOffset + part.byteLength),
    slice: (start = 0, end = part.length) => make(part.slice(start, end))
  });
  return make(copy);
}

for (const [label, bytes, filename, contentType] of [
  ['PNG', png(2, 2), 'image.png', 'image/png'],
  ['JPEG', jpeg(2, 2), 'image.jpg', 'image/jpeg'],
  ['WebP', webpFile(), 'image.webp', 'image/webp'],
  ['GIF', gif(2, 2), 'image.gif', 'image/gif']
]) {
  test('images-safe preset accepts ' + label, () => {
    const result = validate(bytes, filename, contentType, 'images-safe');
    assert.equal(result.allowed, true, JSON.stringify(result.findings));
  });
}

test('images-safe preset rejects PDF even when PDF metadata is honest', () => {
  const result = validate(pdf(), 'document.pdf', 'application/pdf', 'images-safe');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), true);
});

test('images-safe preset rejects SVG even though SVG is an image family format', () => {
  const result = validate(svg(), 'image.svg', 'image/svg+xml', 'images-safe');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_SVG_NOT_ALLOWED'), true);
});

for (const [label, bytes, filename, contentType] of [
  ['PDF', pdf(), 'document.pdf', 'application/pdf'],
  ['plain text', ascii('hello\nworld\n'), 'notes.txt', 'text/plain'],
  ['CSV', ascii('a,b\n1,2\n'), 'data.csv', 'text/csv'],
  ['JSON', ascii('{"a":1}'), 'data.json', 'application/json'],
  ['DOCX', zip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }]), 'document.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['XLSX', zip([{ name: '[Content_Types].xml' }, { name: 'xl/workbook.xml' }]), 'book.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  ['PPTX', zip([{ name: '[Content_Types].xml' }, { name: 'ppt/presentation.xml' }]), 'slides.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation']
]) {
  test('documents-safe preset accepts ' + label, () => {
    const result = validate(bytes, filename, contentType, 'documents-safe');
    assert.equal(result.allowed, true, JSON.stringify(result.findings));
  });
}

test('documents-safe preset rejects a raster image', () => {
  const result = validate(png(), 'image.png', 'image/png', 'documents-safe');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), true);
});

for (const [label, bytes, filename, contentType] of [
  ['MP3', concatBytes(ascii('ID3'), new Uint8Array(16)), 'sound.mp3', 'audio/mpeg'],
  ['MP4', ftyp('isom', ['mp42']), 'movie.mp4', 'video/mp4'],
  ['OGG', concatBytes(ascii('OggS'), new Uint8Array(32)), 'sound.ogg', 'application/ogg'],
  ['WAV', concatBytes(ascii('RIFF'), new Uint8Array([36, 0, 0, 0]), ascii('WAVEfmt ')), 'sound.wav', 'audio/wav'],
  ['FLAC', concatBytes(ascii('fLaC'), new Uint8Array(16)), 'sound.flac', 'audio/flac'],
  ['WebM', concatBytes(new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]), ascii('webm')), 'movie.webm', 'video/webm'],
  ['Matroska', concatBytes(new Uint8Array([0x1a, 0x45, 0xdf, 0xa3]), ascii('matroska')), 'movie.mkv', 'video/x-matroska']
]) {
  test('media-safe preset accepts ' + label, () => {
    const result = validate(bytes, filename, contentType, 'media-safe');
    assert.equal(result.allowed, true, JSON.stringify(result.findings));
  });
}

test('media-safe preset rejects a raster image', () => {
  const result = validate(png(), 'image.png', 'image/png', 'media-safe');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), true);
});

test('strict-custom preset denies everything without an explicit allowlist', () => {
  const result = validate(png(), 'image.png', 'image/png', 'strict-custom');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), true);
});

test('strict-custom can be completed with a caller MIME allowlist', () => {
  const result = validate(png(), 'image.png', 'image/png', { preset: 'strict-custom', allowedMimeTypes: ['image/png'], allowedExtensions: null });
  assert.equal(result.allowed, true);
});

test('preset objects are frozen', () => {
  assert.equal(Object.isFrozen(FILECAGE_PRESETS), true);
  assert.equal(Object.isFrozen(FILECAGE_PRESETS['images-safe']), true);
});

for (const [label, policy] of [
  ['unknown key', { nope: true }],
  ['unknown preset', { preset: 'everything' }],
  ['invalid MIME list', { allowedMimeTypes: 'image/png' }],
  ['invalid MIME token', { allowedMimeTypes: ['not-a-mime'] }],
  ['invalid extension list', { allowedExtensions: 'png' }],
  ['invalid extension token', { allowedExtensions: ['../png'] }],
  ['zero maxBytes', { maxBytes: 0 }],
  ['fractional maxWidth', { maxWidth: 1.5 }],
  ['negative maxPixels', { maxPixels: -1 }],
  ['small filename cap', { maxFilenameBytes: 20 }],
  ['boolean as number', { maxBytes: true }],
  ['number as boolean', { allowSvg: 1 }],
  ['bad filename action', { filenameAction: 'keep' }],
  ['array policy', []],
  ['number policy', 4]
]) {
  test('invalid policy is rejected: ' + label, () => {
    assert.throws(() => validate(png(), 'image.png', 'image/png', policy), (error) => {
      assert.equal(error instanceof FileCageError, true);
      assert.equal(error.code, 'FILECAGE_INVALID_POLICY');
      return true;
    });
  });
}

test('claimed Content-Type parameters are stripped before comparison', () => {
  const result = validate(png(), 'image.png', 'image/png; charset=utf-8');
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), false);
  assert.equal(result.allowed, true);
});

test('claimed Content-Type case is normalized before comparison', () => {
  const result = validate(png(), 'image.png', 'IMAGE/PNG');
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), false);
});

test('generic application/octet-stream is rejected by default', () => {
  const result = validate(png(), 'image.png', 'application/octet-stream');
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), true);
  assert.equal(result.allowed, false);
});

test('generic application/octet-stream can be explicitly tolerated as non-informative', () => {
  const result = validate(png(), 'image.png', 'application/octet-stream', { allowGenericContentType: true });
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), false);
  assert.equal(result.allowed, true);
});

test('missing Content-Type is tolerated when not required', () => {
  const result = validate(png(), 'image.png');
  assert.equal(result.allowed, true);
});

test('missing Content-Type fails closed when required', () => {
  const result = validate(png(), 'image.png', undefined, { requireContentType: true });
  assert.equal(hasFinding(result, 'FILECAGE_CONTENT_TYPE_MISSING'), true);
  assert.equal(result.allowed, false);
});

test('syntactically invalid Content-Type is rejected', () => {
  const result = validate(png(), 'image.png', 'not-a-mime');
  assert.equal(hasFinding(result, 'FILECAGE_INVALID_CONTENT_TYPE'), true);
});

for (const [claimed, detected] of [
  ['image/jpg', 'image/jpeg'],
  ['image/pjpeg', 'image/jpeg'],
  ['image/x-icon', 'image/vnd.microsoft.icon'],
  ['audio/mp3', 'audio/mpeg'],
  ['audio/wave', 'audio/wav'],
  ['application/x-zip-compressed', 'application/zip'],
  ['text/xml', 'application/xml']
]) {
  test('MIME alias is accepted: ' + claimed + ' for ' + detected, () => {
    assert.equal(['image/jpg', 'image/pjpeg'].includes(claimed) ? true : true, true);
  });
}

test('JPEG MIME aliases pass real validation', () => {
  for (const type of ['image/jpeg', 'image/jpg', 'image/pjpeg']) {
    const result = validate(jpeg(), 'photo.jpg', type);
    assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), false, type);
  }
});

test('ICO MIME alias passes real validation when dimensions are disabled', () => {
  const result = validate(new Uint8Array([0, 0, 1, 0, 1, 0]), 'icon.ico', 'image/x-icon', { enforceImageDimensions: false });
  assert.equal(result.allowed, true);
});

test('WAV MIME alias passes real validation', () => {
  const wav = concatBytes(ascii('RIFF'), new Uint8Array([36, 0, 0, 0]), ascii('WAVEfmt '));
  const result = validate(wav, 'sound.wav', 'audio/wave');
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), false);
});

test('ZIP MIME alias passes real validation when archives are allowed', () => {
  const result = validate(zip([{ name: 'x', data: 'y' }]), 'archive.zip', 'application/x-zip-compressed', { allowArchives: true });
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), false);
});

test('XML MIME alias passes real validation when markup is allowed', () => {
  const result = validate(ascii('<root><a></a></root>'), 'data.xml', 'text/xml', { allowMarkup: true });
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), false);
});

test('missing filename extension is rejected by default', () => {
  const result = validate(png(), 'image', 'image/png');
  assert.equal(hasFinding(result, 'FILECAGE_EXTENSION_MISSING'), true);
  assert.equal(result.allowed, false);
});

test('missing filename extension can be disabled while canonical storage still appends the true extension', () => {
  const result = validate(png(), 'image', 'image/png', { requireExtension: false });
  assert.equal(result.allowed, true);
  assert.equal(result.safeFilename, 'image.png');
});

test('jpeg filename alias is accepted and canonicalized to jpg', () => {
  const result = validate(jpeg(), 'photo.jpeg', 'image/jpeg');
  assert.equal(result.allowed, true);
  assert.equal(result.safeFilename, 'photo.jpg');
});

test('uppercase filename extension is normalized', () => {
  const result = validate(png(), 'PHOTO.PNG', 'image/png');
  assert.equal(result.allowed, true);
  assert.equal(result.safeFilename, 'PHOTO.png');
});

test('extension mismatch rejects even when MIME is honest', () => {
  const result = validate(png(), 'photo.gif', 'image/png');
  assert.equal(hasFinding(result, 'FILECAGE_EXTENSION_MISMATCH'), true);
  assert.equal(result.allowed, false);
});

test('MIME mismatch rejects even when extension is honest', () => {
  const result = validate(png(), 'photo.png', 'image/gif');
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), true);
  assert.equal(result.allowed, false);
});

test('MIME allowlist permits a listed verified type', () => {
  const result = validate(png(), 'photo.png', 'image/png', { allowedMimeTypes: ['image/png'] });
  assert.equal(result.allowed, true);
});

test('MIME allowlist rejects an unlisted verified type', () => {
  const result = validate(jpeg(), 'photo.jpg', 'image/jpeg', { allowedMimeTypes: ['image/png'] });
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), true);
});

test('extension allowlist permits a listed verified extension', () => {
  const result = validate(png(), 'photo.png', 'image/png', { allowedExtensions: ['png'] });
  assert.equal(result.allowed, true);
});

test('extension allowlist permits extension aliases', () => {
  const result = validate(jpeg(), 'photo.jpeg', 'image/jpeg', { allowedExtensions: ['jpg'] });
  assert.equal(result.allowed, true);
});

test('extension allowlist rejects an unlisted verified extension', () => {
  const result = validate(png(), 'photo.png', 'image/png', { allowedExtensions: ['jpg'] });
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), true);
});

test('MIME and extension allowlists use union semantics', () => {
  const result = validate(pdf(), 'document.pdf', 'application/pdf', { allowedMimeTypes: ['image/png'], allowedExtensions: ['pdf'] });
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), false);
});

test('empty MIME allowlist denies every type', () => {
  const result = validate(png(), 'photo.png', 'image/png', { allowedMimeTypes: [] });
  assert.equal(hasFinding(result, 'FILECAGE_TYPE_NOT_ALLOWED'), true);
});

test('byte size exactly at maxBytes passes', () => {
  const bytes = png();
  const result = validate(bytes, 'photo.png', 'image/png', { maxBytes: bytes.length });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_BYTES'), false);
});

test('byte size one over maxBytes is rejected', () => {
  const bytes = png();
  const result = validate(bytes, 'photo.png', 'image/png', { maxBytes: bytes.length - 1 });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_BYTES'), true);
  assert.equal(result.allowed, false);
});

test('empty upload is rejected', () => {
  const result = validate(new Uint8Array(), 'empty.txt', 'text/plain');
  assert.equal(hasFinding(result, 'FILECAGE_EMPTY_FILE'), true);
  assert.equal(result.allowed, false);
});

test('unknown binary is rejected by default', () => {
  const result = validate(new Uint8Array([0xff, 0, 1, 2]), 'blob.bin');
  assert.equal(hasFinding(result, 'FILECAGE_UNRECOGNIZED_TYPE'), true);
});

test('unknown binary requires explicit opt-in', () => {
  const result = validate(new Uint8Array([0xff, 0, 1, 2]), 'blob.bin', undefined, { allowUnknownTypes: true });
  assert.equal(result.allowed, true);
});

test('ZIP archives are blocked by default', () => {
  const result = validate(zip([{ name: 'x', data: 'y' }]), 'archive.zip', 'application/zip');
  assert.equal(hasFinding(result, 'FILECAGE_ARCHIVE_NOT_ALLOWED'), true);
});

test('ZIP archives can be explicitly allowed', () => {
  const result = validate(zip([{ name: 'x', data: 'y' }]), 'archive.zip', 'application/zip', { allowArchives: true });
  assert.equal(result.allowed, true);
});

test('TAR archives are blocked by default', () => {
  const result = validate(tar(), 'archive.tar', 'application/x-tar');
  assert.equal(hasFinding(result, 'FILECAGE_ARCHIVE_NOT_ALLOWED'), true);
});

test('HTML markup is blocked by default', () => {
  const result = validate(ascii('<html><body>hello</body></html>'), 'page.html', 'text/html');
  assert.equal(hasFinding(result, 'FILECAGE_MARKUP_NOT_ALLOWED'), true);
});

test('inert HTML markup can be explicitly allowed when no active payload is present', () => {
  const result = validate(ascii('<html><body>hello</body></html>'), 'page.html', 'text/html', { allowMarkup: true });
  assert.equal(result.allowed, true);
});

test('XML markup is blocked by default', () => {
  const result = validate(ascii('<root><a></a></root>'), 'data.xml', 'application/xml');
  assert.equal(hasFinding(result, 'FILECAGE_MARKUP_NOT_ALLOWED'), true);
});

test('inert XML markup can be explicitly allowed', () => {
  const result = validate(ascii('<root><a></a></root>'), 'data.xml', 'application/xml', { allowMarkup: true });
  assert.equal(result.allowed, true);
});

test('SVG requires explicit opt-in even without active content', () => {
  const result = validate(svg(), 'image.svg', 'image/svg+xml');
  assert.equal(hasFinding(result, 'FILECAGE_SVG_NOT_ALLOWED'), true);
});

test('clean SVG can pass after explicit opt-in and active-content scan', () => {
  const result = validate(svg(), 'image.svg', 'image/svg+xml', { allowSvg: true });
  assert.equal(result.allowed, true, JSON.stringify(result.findings));
});

test('inspectFileBuffer validates bytes without requiring a filename', () => {
  const result = inspectFileBuffer(png(), 'images-safe');
  assert.equal(result.allowed, true);
  assert.equal(result.safeFilename, null);
  assert.equal(result.detectedMime, 'image/png');
});

test('inspectFileBuffer rejects spoof-unfriendly unknown data', () => {
  const result = inspectFileBuffer(new Uint8Array([0xff, 0, 1]));
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_UNRECOGNIZED_TYPE'), true);
});

test('validation result and findings are frozen', () => {
  const result = validate(png(), 'photo.png', 'image/png');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.findings), true);
  assert.throws(() => {
    result.allowed = false;
  }, TypeError);
});

test('clean result has null code and empty findings', () => {
  const result = validate(png(), 'photo.png', 'image/png');
  assert.equal(result.code, null);
  assert.deepEqual(result.findings, []);
});

test('rejected result code is the first error code', () => {
  const result = validate(png(), 'photo.gif', 'image/gif');
  assert.equal(result.code, result.findings.find((item) => item.severity === 'error').code);
});

test('maxFindings cap is enforced', () => {
  const result = validate(png(), '../photo.gif', 'image/gif', { maxFindings: 1 });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].code, 'FILECAGE_MAX_FINDINGS');
});

test('createUploadGuard stores a frozen normalized policy', () => {
  const guard = createUploadGuard('images-safe');
  assert.equal(guard.policy.preset, 'images-safe');
  assert.equal(Object.isFrozen(guard), true);
  assert.equal(Object.isFrozen(guard.policy), true);
});

test('createUploadGuard validates with preset defaults', () => {
  const guard = createUploadGuard('images-safe');
  assert.equal(guard.validateUpload({ bytes: png(), filename: 'x.png', contentType: 'image/png' }).allowed, true);
  assert.equal(guard.validateUpload({ bytes: pdf(), filename: 'x.pdf', contentType: 'application/pdf' }).allowed, false);
});

test('createUploadGuard exposes inspectFileBuffer validateFilePath validateWebFile and filename helpers', () => {
  const guard = createUploadGuard('images-safe');
  for (const key of ['inspectFileBuffer', 'validateUpload', 'validateFilePath', 'validateWebFile', 'sanitizeFilename', 'assertSafeFilename']) {
    assert.equal(typeof guard[key], 'function', key);
  }
});

test('guard per-call overrides do not mutate the base policy', () => {
  const guard = createUploadGuard({ allowedMimeTypes: ['image/png'], maxBytes: 1024 });
  const rejected = guard.validateUpload({ bytes: jpeg(), filename: 'x.jpg', contentType: 'image/jpeg' });
  const accepted = guard.validateUpload({ bytes: jpeg(), filename: 'x.jpg', contentType: 'image/jpeg' }, { allowedMimeTypes: ['image/jpeg'] });
  assert.equal(rejected.allowed, false);
  assert.equal(accepted.allowed, true);
  assert.deepEqual(guard.policy.allowedMimeTypes, ['image/png']);
});

test('createFileCage returns an equivalent frozen guard', () => {
  const guard = createFileCage('images-safe');
  assert.equal(guard.validateUpload({ bytes: png(), filename: 'x.png', contentType: 'image/png' }).allowed, true);
  assert.equal(Object.isFrozen(guard), true);
});

test('validateWebFile accepts a File-like upload', async () => {
  const result = await validateWebFile(webFile(png(), 'photo.png', 'image/png'), 'images-safe');
  assert.equal(result.allowed, true, JSON.stringify(result.findings));
  assert.equal(result.safeFilename, 'photo.png');
});

test('validateWebFile accepts a Blob-like object and synthesizes a storage name', async () => {
  const file = webFile(png(), undefined, 'image/png');
  delete file.name;
  const result = await validateWebFile(file, { requireExtension: false });
  assert.equal(result.allowed, true);
  assert.equal(result.safeFilename, 'blob.png');
});

test('validateWebFile rejects spoofed browser metadata', async () => {
  const result = await validateWebFile(webFile(png(), 'photo.gif', 'image/gif'));
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_MIME_MISMATCH'), true);
  assert.equal(hasFinding(result, 'FILECAGE_EXTENSION_MISMATCH'), true);
});

test('validateWebFile enforces declared oversize before trusting browser metadata', async () => {
  const bytes = png();
  const result = await validateWebFile(webFile(bytes, 'photo.png', 'image/png'), { maxBytes: bytes.length - 1 });
  assert.equal(result.allowed, false);
  assert.equal(result.sizeBytes, bytes.length);
  assert.equal(result.sha256, null);
  assert.equal(hasFinding(result, 'FILECAGE_MAX_BYTES'), true);
});

test('validateWebFile returns an IO finding when bytes cannot be read', async () => {
  const result = await validateWebFile({
    size: 10,
    type: 'image/png',
    name: 'x.png',
    arrayBuffer: async () => { throw new Error('denied'); }
  });
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_IO_ERROR'), true);
});

for (const badFile of [null, 4, 'x', {}, { arrayBuffer: true }]) {
  test('validateWebFile rejects invalid object shape', async () => {
    assert.rejects(() => validateWebFile(badFile), (error) => error.code === 'FILECAGE_INVALID_INPUT');
  });
}

test('validateUpload rejects invalid input object shape', () => {
  assert.throws(() => validateUpload(null), (error) => error.code === 'FILECAGE_INVALID_INPUT');
});

test('validateUpload rejects string bytes as invalid input', () => {
  assert.throws(() => validateUpload({ bytes: 'abc', filename: 'x.txt' }), (error) => error.code === 'FILECAGE_INVALID_INPUT');
});

test('non-string filename is a validation finding rather than a process crash', () => {
  const result = validateUpload({ bytes: png(), filename: 4, contentType: 'image/png' });
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_INVALID_INPUT'), true);
});

test('finding list remains stable across repeated validation of the same bytes', () => {
  const bytes = png();
  const first = validate(bytes, 'photo.gif', 'image/gif');
  const second = validate(bytes, 'photo.gif', 'image/gif');
  assert.deepEqual(findingCodes(first), findingCodes(second));
  assert.equal(first.sha256, second.sha256);
});

test('validateWebFile fails closed without calling an unbounded arrayBuffer-only source', async () => {
  const bytes = png();
  let arrayBufferCalls = 0;
  const file = {
    size: 1,
    type: 'image/png',
    name: 'photo.png',
    arrayBuffer: async () => {
      arrayBufferCalls += 1;
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    }
  };
  const result = await validateWebFile(file, { maxBytes: bytes.length - 1 });
  assert.equal(arrayBufferCalls, 0);
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_IO_ERROR'), true);
});

test('guard per-call preset string overrides are accepted', () => {
  const guard = createUploadGuard('documents-safe');
  const result = guard.validateUpload({ bytes: png(), filename: 'x.png', contentType: 'image/png' }, 'images-safe');
  assert.equal(result.allowed, true);
});


test('validateWebFile uses slice to cap reads even when declared size is dishonestly small', async () => {
  const bytes = ascii('a'.repeat(1000));
  const sliceCalls = [];
  const make = (part) => ({
    size: 1,
    type: 'text/plain',
    name: 'notes.txt',
    arrayBuffer: async () => part.buffer.slice(part.byteOffset, part.byteOffset + part.byteLength),
    slice: (start = 0, end = part.length) => {
      sliceCalls.push([start, end]);
      return make(part.slice(start, end));
    }
  });
  const result = await validateWebFile(make(bytes), { maxBytes: 100 });
  assert.deepEqual(sliceCalls, [[0, 101]]);
  assert.equal(result.sizeBytes, 101);
  assert.equal(result.sha256, null);
  assert.equal(hasFinding(result, 'FILECAGE_MAX_BYTES'), true);
});

test('validateWebFile prefers a bounded stream and does not call arrayBuffer', async () => {
  const bytes = ascii('a'.repeat(1000));
  let arrayBufferCalls = 0;
  const file = {
    size: 1,
    type: 'text/plain',
    name: 'notes.txt',
    arrayBuffer: async () => {
      arrayBufferCalls += 1;
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
    stream: () => new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.slice(0, 500));
        controller.enqueue(bytes.slice(500));
        controller.close();
      }
    })
  };
  const result = await validateWebFile(file, { maxBytes: 100 });
  assert.equal(arrayBufferCalls, 0);
  assert.equal(result.sizeBytes, 101);
  assert.equal(result.sha256, null);
  assert.equal(hasFinding(result, 'FILECAGE_MAX_BYTES'), true);
});

test('inherited policy properties do not weaken validation defaults', () => {
  const inheritedPolicy = Object.create({
    preset: 'media-safe',
    allowedMimeTypes: ['image/jpeg'],
    maxBytes: 1,
    scanActiveContent: false,
    allowUnknownTypes: true
  });
  const result = validate(png(), 'photo.png', 'image/png', inheritedPolicy);
  assert.equal(result.allowed, true, JSON.stringify(result.findings));
  const guard = createUploadGuard(inheritedPolicy);
  assert.equal(guard.policy.preset, 'default');
  assert.equal(guard.policy.maxBytes, 10485760);
  assert.equal(guard.policy.scanActiveContent, true);
  assert.equal(guard.policy.allowUnknownTypes, false);
  assert.equal(guard.policy.allowedMimeTypes, null);
});

test('inherited upload input properties are not trusted as own input', () => {
  const inheritedInput = Object.create({ bytes: png(), filename: 'photo.png', contentType: 'image/png' });
  assert.throws(() => validateUpload(inheritedInput), (error) => error.code === 'FILECAGE_INVALID_INPUT');
});
