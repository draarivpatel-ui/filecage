import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { validateUpload } from '../src/index.mjs';
import { ascii, concatBytes, png, jpeg, gif, webpVp8, bmp, pdf, svg, validate, hasFinding, findingCodes } from './helpers.mjs';

function validateSvg(bytes, policy = {}) {
  return validateUpload({ bytes, filename: 'image.svg', contentType: 'image/svg+xml' }, { allowSvg: true, ...policy });
}

for (const [label, body] of [
  ['lowercase script element', '<script>alert(1)</script>'],
  ['uppercase script element', '<SCRIPT>alert(1)</SCRIPT>'],
  ['mixed-case script element', '<sCrIpT>alert(1)</sCrIpT>'],
  ['namespaced script element', '<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>'],
  ['script with whitespace after bracket', '< script>alert(1)</script>']
]) {
  test('SVG script active content is rejected: ' + label, () => {
    const result = validateSvg(svg(body));
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_SVG_ACTIVE_CONTENT'), true);
  });
}

for (const attribute of ['onload', 'onclick', 'onerror', 'onbegin', 'onrepeat', 'onfocusin', 'ONLOAD', 'onload ']) {
  test('SVG event handler attribute is rejected: ' + attribute, () => {
    const result = validateSvg(svg('<rect ' + attribute + '="alert(1)"/>'));
    assert.equal(result.allowed, false);
    assert.equal(result.findings.some((item) => item.code === 'FILECAGE_SVG_ACTIVE_CONTENT' && item.pattern === 'event-handler'), true);
  });
}

for (const [label, href] of [
  ['javascript href', 'javascript:alert(1)'],
  ['uppercase javascript href', 'JaVaScRiPt:alert(1)'],
  ['whitespace-obfuscated javascript href', 'java\nscript:alert(1)'],
  ['numeric entity javascript href', 'java&#x73;cript:alert(1)'],
  ['decimal entity javascript href', 'java&#115;cript:alert(1)'],
  ['data href', 'data:text/html;base64,PHNjcmlwdD4=']
]) {
  test('SVG active href is rejected: ' + label, () => {
    const result = validateSvg(svg('<a href="' + href + '"><text>x</text></a>'));
    assert.equal(result.allowed, false);
    assert.equal(result.findings.some((item) => item.code === 'FILECAGE_SVG_ACTIVE_CONTENT' && item.pattern && item.pattern.endsWith('-href')), true);
  });
}

test('SVG single-quoted javascript href is rejected', () => {
  const result = validateSvg(svg("<a href='javascript:alert(1)'><text>x</text></a>"));
  assert.equal(hasFinding(result, 'FILECAGE_SVG_ACTIVE_CONTENT'), true);
});

test('SVG foreignObject is rejected', () => {
  const result = validateSvg(svg('<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>'));
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.pattern === 'foreignObject'), true);
});

test('SVG mixed-case foreignObject is rejected', () => {
  const result = validateSvg(svg('<foreignobject><div>x</div></foreignobject>'));
  assert.equal(hasFinding(result, 'FILECAGE_SVG_ACTIVE_CONTENT'), true);
});

test('SVG DOCTYPE is rejected as an XXE risk', () => {
  const bytes = ascii('<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>');
  const result = validateSvg(bytes);
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.code === 'FILECAGE_SVG_XXE' && item.pattern === 'doctype'), true);
});

test('SVG ENTITY declaration is rejected as an XXE risk', () => {
  const bytes = ascii('<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>');
  const result = validateSvg(bytes);
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.code === 'FILECAGE_SVG_XXE' && item.pattern === 'entity'), true);
});

for (const [label, attribute] of [
  ['http use href', 'href="http://example.invalid/a.svg#x"'],
  ['https use href', 'href="https://example.invalid/a.svg#x"'],
  ['protocol-relative use href', 'href="//example.invalid/a.svg#x"'],
  ['xlink use href', 'xlink:href="https://example.invalid/a.svg#x"']
]) {
  test('SVG remote use reference is rejected: ' + label, () => {
    const result = validateSvg(svg('<use ' + attribute + '/>'));
    assert.equal(result.allowed, false);
    assert.equal(result.findings.some((item) => item.pattern === 'remote-use'), true);
  });
}

test('SVG local fragment use reference can pass', () => {
  const result = validateSvg(svg('<use href="#shape"/>'));
  assert.equal(result.allowed, true, JSON.stringify(result.findings));
});

test('clean SVG passes after explicit opt-in', () => {
  const result = validateSvg(svg('<circle cx="5" cy="5" r="4"/>'));
  assert.equal(result.allowed, true);
});

test('SVG remains blocked without explicit opt-in even when clean', () => {
  const result = validate(svg(), 'image.svg', 'image/svg+xml');
  assert.equal(hasFinding(result, 'FILECAGE_SVG_NOT_ALLOWED'), true);
});

function validatePdf(bytes, policy = {}) {
  return validateUpload({ bytes, filename: 'document.pdf', contentType: 'application/pdf' }, policy);
}

for (const name of ['JavaScript', 'JS', 'Launch', 'OpenAction', 'AA', 'EmbeddedFile', 'URI']) {
  test('PDF active action /' + name + ' is rejected', () => {
    const result = validatePdf(pdf('2 0 obj << /' + name + ' true >> endobj'));
    assert.equal(result.allowed, false);
    assert.equal(result.findings.some((item) => item.code === 'FILECAGE_PDF_ACTIVE_CONTENT' && item.token === '/' + name.toUpperCase()), true);
  });
}

test('PDF hex-obfuscated JavaScript name is decoded and rejected', () => {
  const result = validatePdf(pdf('2 0 obj << /J#61vaScript true >> endobj'));
  assert.equal(result.findings.some((item) => item.token === '/JAVASCRIPT'), true);
});

test('PDF URI action can be explicitly tolerated', () => {
  const result = validatePdf(pdf('2 0 obj << /URI (https://example.invalid/) >> endobj'), { allowPdfUri: true });
  assert.equal(result.findings.some((item) => item.token === '/URI'), false);
});

test('clean PDF passes active-content scan', () => {
  const result = validatePdf(pdf());
  assert.equal(result.allowed, true, JSON.stringify(result.findings));
});

function compressedObjectStreamPdf(payload, compressed = true) {
  const data = compressed ? deflateSync(ascii(payload)) : ascii(payload);
  return concatBytes(
    ascii('%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /N 1 /First 0 /Filter /FlateDecode /Length ' + data.length + ' >>\nstream\n'),
    data,
    ascii('\nendstream\nendobj\n%%EOF\n')
  );
}

test('PDF JavaScript hidden in a FlateDecode object stream is rejected', () => {
  const result = validatePdf(compressedObjectStreamPdf('/Type /OpenAction /S /JavaScript /JS (alert(1))'));
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.token === '/JAVASCRIPT'), true);
});

test('PDF Launch hidden in a FlateDecode object stream is rejected', () => {
  const result = validatePdf(compressedObjectStreamPdf('/Type /Action /S /Launch'));
  assert.equal(result.findings.some((item) => item.token === '/LAUNCH'), true);
});

test('malformed compressed PDF object stream fails closed', () => {
  const result = validatePdf(compressedObjectStreamPdf('/Type /OpenAction', false));
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_PDF_SCAN_LIMIT'), true);
});

function validateImage(bytes, filename, type, policy = {}) {
  return validateUpload({ bytes, filename, contentType: type }, policy);
}

const zipLocal = ascii('PK\x03\x04payload');
const zipEnd = new Uint8Array([0x50, 0x4b, 0x05, 0x06, ...new Array(18).fill(0)]);
for (const [label, make, filename, type] of [
  ['PNG', () => png(1, 1), 'image.png', 'image/png'],
  ['JPEG', () => jpeg(1, 1), 'image.jpg', 'image/jpeg'],
  ['GIF', () => gif(1, 1), 'image.gif', 'image/gif'],
  ['WebP', () => webpVp8(1, 1), 'image.webp', 'image/webp'],
  ['BMP', () => bmp(1, 1), 'image.bmp', 'image/bmp']
]) {
  test(label + ' with appended ZIP local header is rejected as a polyglot', () => {
    const result = validateImage(concatBytes(make(), zipLocal), filename, type);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_POLYGLOT'), true);
  });
  test(label + ' with appended ZIP end record is rejected as a polyglot', () => {
    const result = validateImage(concatBytes(make(), zipEnd), filename, type);
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_POLYGLOT'), true);
  });
}

test('GIFAR-style GIF plus JAR trailer is rejected', () => {
  const jarTrailer = concatBytes(ascii('PK\x03\x04'), ascii('META-INF/MANIFEST.MF'));
  const result = validateImage(concatBytes(gif(), jarTrailer), 'avatar.gif', 'image/gif');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_POLYGLOT'), true);
});

test('JPEG plus ZIP polyglot is rejected even when metadata is honest', () => {
  const result = validateImage(concatBytes(jpeg(), zipLocal), 'photo.jpg', 'image/jpeg');
  assert.equal(hasFinding(result, 'FILECAGE_POLYGLOT'), true);
});

test('PNG with non-ZIP data after IEND is rejected as trailing data', () => {
  const result = validateImage(png(1, 1, { trailing: ascii('extra') }), 'image.png', 'image/png');
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_TRAILING_DATA'), true);
  assert.equal(hasFinding(result, 'FILECAGE_POLYGLOT'), false);
});

test('clean PNG does not produce polyglot or trailing findings', () => {
  const result = validateImage(png(), 'image.png', 'image/png');
  assert.equal(hasFinding(result, 'FILECAGE_POLYGLOT'), false);
  assert.equal(hasFinding(result, 'FILECAGE_TRAILING_DATA'), false);
  assert.equal(result.allowed, true);
});

test('polyglot scanning can be disabled only by explicit policy', () => {
  const result = validateImage(concatBytes(jpeg(), zipLocal), 'photo.jpg', 'image/jpeg', { scanPolyglots: false });
  assert.equal(hasFinding(result, 'FILECAGE_POLYGLOT'), false);
});

for (const [label, payload, pattern] of [
  ['script tag', '<script>alert(1)</script>', 'script-tag'],
  ['HTML doctype', '<!DOCTYPE html><html></html>', 'html-doctype'],
  ['iframe', '<iframe src="https://example.invalid"></iframe>', 'iframe'],
  ['object', '<object data="x"></object>', 'object'],
  ['embed', '<embed src="x">', 'embed'],
  ['embedded SVG', '<svg><script>x</script></svg>', 'svg'],
  ['PHP tag', '<?php system($_GET[1]); ?>', 'php-tag'],
  ['PHP short echo', '<?= system($_GET[1]) ?>', 'php-short-echo'],
  ['ASP tag', '<% eval request %>', 'asp-tag']
]) {
  test('active payload in plain text is rejected: ' + label, () => {
    const bytes = ascii('prefix text\n' + payload + '\nsuffix text\n');
    const result = validate(bytes, 'notes.txt', 'text/plain');
    assert.equal(result.allowed, false);
    assert.equal(result.findings.some((item) => item.code === 'FILECAGE_ACTIVE_CONTENT' && item.pattern === pattern), true);
  });
}

for (const [label, payload] of [
  ['script tag', '<script>alert(1)</script>'],
  ['PHP tag', '<?php echo 1; ?>'],
  ['ASP tag', '<% response.write 1 %>'],
  ['embedded SVG', '<svg><script>x</script></svg>']
]) {
  test('active payload appended to PNG is rejected: ' + label, () => {
    const result = validateImage(png(1, 1, { trailing: ascii(payload) }), 'image.png', 'image/png');
    assert.equal(result.allowed, false);
    assert.equal(hasFinding(result, 'FILECAGE_ACTIVE_CONTENT'), true);
  });
}

test('active-content scanning can be disabled only by explicit policy', () => {
  const result = validate(ascii('text\n<?php echo 1; ?>\n'), 'notes.txt', 'text/plain', { scanActiveContent: false });
  assert.equal(hasFinding(result, 'FILECAGE_ACTIVE_CONTENT'), false);
});

test('HTML with script is rejected even when markup is allowed', () => {
  const result = validate(ascii('<html><body><script>alert(1)</script></body></html>'), 'page.html', 'text/html', { allowMarkup: true });
  assert.equal(result.allowed, false);
  assert.equal(hasFinding(result, 'FILECAGE_ACTIVE_CONTENT'), true);
});

test('inert HTML without script iframe object or embed can pass when markup is allowed', () => {
  const result = validate(ascii('<html><body><p>hello</p></body></html>'), 'page.html', 'text/html', { allowMarkup: true });
  assert.equal(result.allowed, true);
});

test('PDF embedded JavaScript-like text and PDF names are both represented in stable finding codes', () => {
  const result = validatePdf(pdf('2 0 obj << /JavaScript true >> endobj'));
  assert.equal(findingCodes(result).includes('FILECAGE_PDF_ACTIVE_CONTENT'), true);
});

test('HTML containing inline SVG is rejected as embedded active content', () => {
  const result = validate(ascii('<html><body><svg onload="alert(1)"></svg></body></html>'), 'page.html', 'text/html', { allowMarkup: true });
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((item) => item.code === 'FILECAGE_ACTIVE_CONTENT' && item.pattern === 'svg'), true);
});
