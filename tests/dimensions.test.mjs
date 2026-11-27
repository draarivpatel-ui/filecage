import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectImageDimensions, validateUpload } from '../src/index.mjs';
import { png, jpeg, gif, webpVp8, webpVp8l, webpVp8x, bmp, ftyp, validate, hasFinding } from './helpers.mjs';

const dimensionSets = [
  [1, 1], [2, 3], [320, 200], [4096, 2160], [10000, 9999]
];

for (const [width, height] of dimensionSets) {
  test('PNG IHDR dimensions are parsed for ' + width + 'x' + height, () => {
    assert.deepEqual(inspectImageDimensions(png(width, height)), { format: 'png', width, height, pixels: width * height });
  });
  test('JPEG SOF dimensions are parsed for ' + width + 'x' + height, () => {
    assert.deepEqual(inspectImageDimensions(jpeg(width, height)), { format: 'jpeg', width, height, pixels: width * height });
  });
  test('GIF logical screen dimensions are parsed for ' + width + 'x' + height, () => {
    assert.deepEqual(inspectImageDimensions(gif(width, height)), { format: 'gif', width, height, pixels: width * height });
  });
  test('lossy WebP dimensions are parsed for ' + width + 'x' + height, () => {
    assert.deepEqual(inspectImageDimensions(webpVp8(width, height)), { format: 'webp', width, height, pixels: width * height });
  });
  test('lossless WebP dimensions are parsed for ' + width + 'x' + height, () => {
    assert.deepEqual(inspectImageDimensions(webpVp8l(width, height)), { format: 'webp', width, height, pixels: width * height });
  });
  test('extended WebP dimensions are parsed for ' + width + 'x' + height, () => {
    assert.deepEqual(inspectImageDimensions(webpVp8x(width, height)), { format: 'webp', width, height, pixels: width * height });
  });
  test('BMP DIB dimensions are parsed for ' + width + 'x' + height, () => {
    assert.deepEqual(inspectImageDimensions(bmp(width, height)), { format: 'bmp', width, height, pixels: width * height });
  });
}

for (const marker of [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]) {
  test('JPEG marker 0x' + marker.toString(16).toUpperCase() + ' is accepted as a start-of-frame', () => {
    assert.deepEqual(inspectImageDimensions(jpeg(17, 19, { marker })), { format: 'jpeg', width: 17, height: 19, pixels: 323 });
  });
}

test('JPEG parsing walks prior APP segments before SOF', () => {
  assert.deepEqual(inspectImageDimensions(jpeg(8, 9, { app0: true })), { format: 'jpeg', width: 8, height: 9, pixels: 72 });
});

test('JPEG parsing skips 0xFF fill bytes before a marker', () => {
  assert.deepEqual(inspectImageDimensions(jpeg(8, 9, { padding: 3 })), { format: 'jpeg', width: 8, height: 9, pixels: 72 });
});

test('JPEG dimension parser does not invoke an image decoder for malformed compressed payloads', () => {
  const bytes = jpeg(40, 30, { trailingFill: 64 });
  assert.deepEqual(inspectImageDimensions(bytes), { format: 'jpeg', width: 40, height: 30, pixels: 1200 });
});

const malformedJpegs = [
  ['zero segment length', jpeg(1, 1, { lengthOverride: 0 })],
  ['one byte segment length', jpeg(1, 1, { lengthOverride: 1 })],
  ['declared segment beyond buffer', jpeg(1, 1, { lengthOverride: 100 })],
  ['too short SOF segment', jpeg(1, 1, { lengthOverride: 3 })],
  ['truncated length field', new Uint8Array([0xff, 0xd8, 0xff, 0xc0, 0x00])],
  ['missing SOF before EOI', new Uint8Array([0xff, 0xd8, 0xff, 0xd9])],
  ['SOS before SOF', new Uint8Array([0xff, 0xd8, 0xff, 0xda, 0x00, 0x02])],
  ['zero width', jpeg(0, 10)],
  ['zero height', jpeg(10, 0)],
  ['truncated file after SOI', new Uint8Array([0xff, 0xd8])],
  ['single byte file', new Uint8Array([0xff])],
  ['empty file', new Uint8Array()]
];
for (const [label, bytes] of malformedJpegs) {
  test('malformed JPEG returns null instead of looping or throwing: ' + label, () => {
    assert.equal(inspectImageDimensions(bytes), null);
  });
}

test('JPEG marker walk remains bounded across many empty segments', () => {
  const parts = [0xff, 0xd8];
  for (let index = 0; index < 1100; index += 1) parts.push(0xff, 0xe1, 0x00, 0x02);
  parts.push(0xff, 0xd9);
  assert.equal(inspectImageDimensions(new Uint8Array(parts)), null);
});

const malformedPngs = [
  ['signature only', png(1, 1, { noIhdr: true })],
  ['missing IHDR length', new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0])],
  ['wrong first chunk', new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x44, 0x41, 0x54])],
  ['zero width', png(0, 1)],
  ['zero height', png(1, 0)]
];
for (const [label, bytes] of malformedPngs) {
  test('malformed PNG dimensions return null: ' + label, () => {
    assert.equal(inspectImageDimensions(bytes), null);
  });
}

test('PNG dimension parser reads large dimensions without decoding image data', () => {
  assert.deepEqual(inspectImageDimensions(png(65535, 65535)), {
    format: 'png', width: 65535, height: 65535, pixels: 65535 * 65535
  });
});

const malformedWebps = [
  ['empty', new Uint8Array()],
  ['bad RIFF type', webpVp8().map((value, index) => index === 9 ? 0x58 : value)],
  ['truncated header', webpVp8().slice(0, 15)],
  ['bad VP8 start code', (() => { const b = webpVp8(); b[23] = 0; return b; })()],
  ['VP8 zero width', webpVp8(0, 1)],
  ['VP8L bad signature', (() => { const b = webpVp8l(); b[20] = 0; return b; })()],
  ['VP8L truncated payload', webpVp8l().slice(0, 23)],
  ['VP8X truncated payload', webpVp8x().slice(0, 27)]
];
for (const [label, bytes] of malformedWebps) {
  test('malformed WebP dimensions return null: ' + label, () => {
    assert.equal(inspectImageDimensions(bytes), null);
  });
}

test('BMP top-down negative height is normalized to a positive height', () => {
  assert.deepEqual(inspectImageDimensions(bmp(7, -11)), { format: 'bmp', width: 7, height: 11, pixels: 77 });
});

test('BMP core header dimensions are parsed', () => {
  assert.deepEqual(inspectImageDimensions(bmp(5, 6, { core: true })), { format: 'bmp', width: 5, height: 6, pixels: 30 });
});

for (const [label, bytes] of [
  ['zero width', bmp(0, 1)],
  ['zero height', bmp(1, 0)],
  ['negative width', (() => { const b = bmp(1, 1); b.set([0xff, 0xff, 0xff, 0xff], 18); return b; })()],
  ['truncated', bmp().slice(0, 20)]
]) {
  test('malformed BMP dimensions return null: ' + label, () => {
    assert.equal(inspectImageDimensions(bytes), null);
  });
}

for (const [label, bytes] of [
  ['zero width', gif(0, 1)],
  ['zero height', gif(1, 0)],
  ['truncated', gif().slice(0, 7)]
]) {
  test('malformed GIF dimensions return null: ' + label, () => {
    assert.equal(inspectImageDimensions(bytes), null);
  });
}

test('inspectImageDimensions returns null for non-image bytes', () => {
  assert.equal(inspectImageDimensions(new TextEncoder().encode('hello')), null);
});

const imageFixtures = [
  ['PNG', () => png(6000, 5000), 'bomb.png', 'image/png'],
  ['JPEG', () => jpeg(6000, 5000), 'bomb.jpg', 'image/jpeg'],
  ['GIF', () => gif(6000, 5000), 'bomb.gif', 'image/gif'],
  ['lossy WebP', () => webpVp8(6000, 5000), 'bomb.webp', 'image/webp'],
  ['BMP', () => bmp(6000, 5000), 'bomb.bmp', 'image/bmp']
];
for (const [label, make, filename, contentType] of imageFixtures) {
  test(label + ' pixel flood is rejected before image decoding', () => {
    const result = validate(make(), filename, contentType);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_MAX_PIXELS'), true);
  });
}

test('a 65535 by 65535 PNG decompression bomb is rejected', () => {
  const result = validate(png(65535, 65535), 'bomb.png', 'image/png');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_MAX_WIDTH'), true);
  assert.equal(hasFinding(result, 'FILECAGE_MAX_HEIGHT'), true);
  assert.equal(hasFinding(result, 'FILECAGE_MAX_PIXELS'), true);
});

test('a 65535 by 65535 JPEG decompression bomb is rejected', () => {
  const result = validate(jpeg(65535, 65535), 'bomb.jpg', 'image/jpeg');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_MAX_PIXELS'), true);
});

test('image width exactly at maxWidth passes that limit', () => {
  const result = validateUpload({ bytes: png(10, 5), filename: 'ok.png', contentType: 'image/png' }, { maxWidth: 10, maxHeight: 20, maxPixels: 200 });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_WIDTH'), false);
  assert.equal(result.allowed, true);
});

test('image width one over maxWidth is rejected', () => {
  const result = validateUpload({ bytes: png(11, 5), filename: 'wide.png', contentType: 'image/png' }, { maxWidth: 10, maxHeight: 20, maxPixels: 200 });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_WIDTH'), true);
  assert.equal(result.allowed, false);
});

test('image height exactly at maxHeight passes that limit', () => {
  const result = validateUpload({ bytes: png(10, 20), filename: 'ok.png', contentType: 'image/png' }, { maxWidth: 10, maxHeight: 20, maxPixels: 200 });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_HEIGHT'), false);
  assert.equal(result.allowed, true);
});

test('image height one over maxHeight is rejected', () => {
  const result = validateUpload({ bytes: png(10, 21), filename: 'tall.png', contentType: 'image/png' }, { maxWidth: 10, maxHeight: 20, maxPixels: 500 });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_HEIGHT'), true);
  assert.equal(result.allowed, false);
});

test('image pixel count exactly at maxPixels passes that limit', () => {
  const result = validateUpload({ bytes: png(10, 20), filename: 'ok.png', contentType: 'image/png' }, { maxWidth: 20, maxHeight: 20, maxPixels: 200 });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_PIXELS'), false);
  assert.equal(result.allowed, true);
});

test('image pixel count one over maxPixels is rejected', () => {
  const result = validateUpload({ bytes: png(10, 22), filename: 'large.png', contentType: 'image/png' }, { maxWidth: 20, maxHeight: 30, maxPixels: 210 });
  assert.equal(hasFinding(result, 'FILECAGE_MAX_PIXELS'), true);
  assert.equal(result.allowed, false);
});

test('malformed image dimensions fail closed in validation', () => {
  const result = validate(png(0, 10), 'broken.png', 'image/png');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_DIMENSIONS_UNREADABLE'), true);
});

test('AVIF is fail-closed when dimension enforcement is enabled', () => {
  const result = validate(ftyp('avif'), 'image.avif', 'image/avif');
  assert.equal(hasFinding(result, 'FILECAGE_DIMENSIONS_UNREADABLE'), true);
  assert.equal(result.allowed, false);
});

test('AVIF can be admitted only when dimension enforcement is explicitly disabled', () => {
  const result = validate(ftyp('avif'), 'image.avif', 'image/avif', { enforceImageDimensions: false });
  assert.equal(result.allowed, true);
});

test('ICO is fail-closed when dimension enforcement is enabled', () => {
  const result = validate(new Uint8Array([0, 0, 1, 0, 1, 0]), 'icon.ico', 'image/vnd.microsoft.icon');
  assert.equal(hasFinding(result, 'FILECAGE_DIMENSIONS_UNREADABLE'), true);
});

test('ICO can be admitted only when dimension enforcement is explicitly disabled', () => {
  const result = validate(new Uint8Array([0, 0, 1, 0, 1, 0]), 'icon.ico', 'image/vnd.microsoft.icon', { enforceImageDimensions: false });
  assert.equal(result.allowed, true);
});

test('validation still reports dimensions when enforcement is disabled', () => {
  const result = validate(png(3, 4), 'small.png', 'image/png', { enforceImageDimensions: false });
  assert.deepEqual(result.dimensions, { format: 'png', width: 3, height: 4, pixels: 12 });
  assert.equal(result.allowed, true);
});

test('dimension result objects are frozen', () => {
  const dimensions = inspectImageDimensions(png(1, 1));
  assert.equal(Object.isFrozen(dimensions), true);
  assert.throws(() => {
    dimensions.width = 99;
  }, TypeError);
});

test('JPEG arbitrary junk before a marker is rejected rather than skipped', () => {
  const valid = jpeg(9, 8);
  const withJunk = new Uint8Array([0xff, 0xd8, 0x00, ...valid.slice(2)]);
  assert.equal(inspectImageDimensions(withJunk), null);
});
