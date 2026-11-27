import { validateUpload } from '../src/index.mjs';

export function ascii(text) {
  return new TextEncoder().encode(text);
}

export function concatBytes(...parts) {
  const arrays = parts.map((part) => part instanceof Uint8Array ? part : ascii(String(part)));
  const total = arrays.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of arrays) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function u16beBytes(value) {
  return [(value >>> 8) & 255, value & 255];
}

export function u16leBytes(value) {
  return [value & 255, (value >>> 8) & 255];
}

export function u32beBytes(value) {
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
}

export function u32leBytes(value) {
  return [value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255];
}

export function png(width = 1, height = 1, options = {}) {
  const bytes = [];
  bytes.push(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
  if (options.noIhdr) return new Uint8Array(bytes);
  bytes.push(...u32beBytes(13), 0x49, 0x48, 0x44, 0x52);
  bytes.push(...u32beBytes(width), ...u32beBytes(height), 8, 2, 0, 0, 0, 0, 0, 0, 0);
  if (options.idat !== false) bytes.push(...u32beBytes(0), 0x49, 0x44, 0x41, 0x54, 0, 0, 0, 0);
  if (options.iend !== false) bytes.push(...u32beBytes(0), 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0);
  const base = new Uint8Array(bytes);
  return options.trailing ? concatBytes(base, options.trailing) : base;
}

export function jpeg(width = 1, height = 1, options = {}) {
  const marker = options.marker === undefined ? 0xc0 : options.marker;
  const componentCount = options.components === undefined ? 1 : options.components;
  const segmentLength = options.lengthOverride === undefined ? 8 + componentCount * 3 : options.lengthOverride;
  const bytes = [0xff, 0xd8];
  if (options.app0) bytes.push(0xff, 0xe0, 0x00, 0x02);
  if (options.padding) bytes.push(...new Array(options.padding).fill(0xff));
  bytes.push(0xff, marker, ...u16beBytes(segmentLength));
  if (!options.noDimensionPayload) {
    bytes.push(8, ...u16beBytes(height), ...u16beBytes(width), componentCount);
    for (let index = 0; index < componentCount * 3; index += 1) bytes.push(1, 0x11, 0);
  }
  if (options.trailingFill) bytes.push(...new Array(options.trailingFill).fill(0));
  if (options.eoi !== false) bytes.push(0xff, 0xd9);
  return new Uint8Array(bytes);
}

export function gif(width = 1, height = 1, options = {}) {
  const version = options.version || 'GIF89a';
  const bytes = [...ascii(version), ...u16leBytes(width), ...u16leBytes(height), 0, 0, 0];
  if (options.trailer !== false) bytes.push(0x3b);
  const base = new Uint8Array(bytes);
  return options.trailing ? concatBytes(base, options.trailing) : base;
}

function riffWebp(type, payload) {
  const padded = payload.length + (payload.length % 2);
  const riffSize = 4 + 8 + padded;
  return new Uint8Array([
    ...ascii('RIFF'), ...u32leBytes(riffSize), ...ascii('WEBP'),
    ...ascii(type), ...u32leBytes(payload.length), ...payload,
    ...(payload.length % 2 ? [0] : [])
  ]);
}

export function webpVp8(width = 1, height = 1) {
  const payload = [
    0, 0, 0, 0x9d, 0x01, 0x2a,
    ...u16leBytes(width), ...u16leBytes(height)
  ];
  return riffWebp('VP8 ', payload);
}

export function webpVp8l(width = 1, height = 1) {
  const bits = (width - 1) | ((height - 1) << 14);
  const payload = [0x2f, bits & 255, (bits >>> 8) & 255, (bits >>> 16) & 255, (bits >>> 24) & 255];
  return riffWebp('VP8L', payload);
}

export function webpVp8x(width = 1, height = 1) {
  const widthMinus = width - 1;
  const heightMinus = height - 1;
  const payload = [
    0, 0, 0, 0,
    widthMinus & 255, (widthMinus >>> 8) & 255, (widthMinus >>> 16) & 255,
    heightMinus & 255, (heightMinus >>> 8) & 255, (heightMinus >>> 16) & 255
  ];
  return riffWebp('VP8X', payload);
}

export function bmp(width = 1, height = 1, options = {}) {
  if (options.core) {
    return new Uint8Array([
      ...ascii('BM'), ...u32leBytes(26), 0, 0, 0, 0, ...u32leBytes(14),
      ...u32leBytes(12), ...u16leBytes(width), ...u16leBytes(height), 1, 0, 24, 0
    ]);
  }
  const storedHeight = height < 0 ? 0x100000000 + height : height;
  return new Uint8Array([
    ...ascii('BM'), ...u32leBytes(54), 0, 0, 0, 0, ...u32leBytes(54),
    ...u32leBytes(40), ...u32leBytes(width), ...u32leBytes(storedHeight),
    1, 0, 24, 0, ...u32leBytes(0), ...u32leBytes(0), ...u32leBytes(0), ...u32leBytes(0), ...u32leBytes(0), ...u32leBytes(0)
  ]);
}

export function zip(entries, options = {}) {
  const parts = [];
  for (const entry of entries) {
    const name = ascii(entry.name);
    const data = entry.data instanceof Uint8Array ? entry.data : ascii(entry.data || '');
    parts.push(new Uint8Array([
      0x50, 0x4b, 0x03, 0x04,
      ...u16leBytes(20), ...u16leBytes(0), ...u16leBytes(0),
      ...u16leBytes(0), ...u16leBytes(0), ...u32leBytes(0),
      ...u32leBytes(data.length), ...u32leBytes(data.length),
      ...u16leBytes(name.length), ...u16leBytes(0)
    ]), name, data);
  }
  if (options.emptyEnd) parts.push(new Uint8Array([0x50, 0x4b, 0x05, 0x06, ...new Array(18).fill(0)]));
  return concatBytes(...parts);
}

export function ftyp(major = 'isom', compatible = []) {
  const size = 16 + compatible.length * 4;
  return new Uint8Array([
    ...u32beBytes(size), ...ascii('ftyp'), ...ascii(major.padEnd(4, ' ').slice(0, 4)), ...u32beBytes(0),
    ...compatible.flatMap((brand) => [...ascii(brand.padEnd(4, ' ').slice(0, 4))])
  ]);
}

export function tar() {
  const output = new Uint8Array(512);
  output.set(ascii('ustar'), 257);
  return output;
}

export function pdf(body = '') {
  return ascii('%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n' + body + '\n%%EOF\n');
}

export function svg(body = '<rect width="10" height="10"/>') {
  return ascii('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">' + body + '</svg>');
}

export function validate(bytes, filename = 'file.bin', contentType = undefined, policy = undefined) {
  return validateUpload({ bytes, filename, contentType }, policy);
}

export function findingCodes(result) {
  return result.findings.map((item) => item.code);
}

export function hasFinding(result, code) {
  return result.findings.some((item) => item.code === code);
}
