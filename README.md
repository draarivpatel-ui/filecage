# filecage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/filecage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/filecage)

Zero-dependency CWE-434 file-upload defense for Node.js.

`filecage` verifies what an upload actually is before application code trusts it.
It never treats a filename or a caller-supplied `Content-Type` as proof. It reads
magic bytes, verifies image dimensions directly from binary headers, rejects
executable and active content, detects common polyglots, and produces a safe
storage filename.

The library ships ESM, CommonJS, TypeScript definitions, and a small CLI from
one audited source of truth. It has zero runtime dependencies. Its only
development dependency is the property-test library fast-check. The deterministic
suite contains exactly 903 tests in this source checkout.

## Publication status

This repository is prepared for npm publication, but publication is a separate
release step. Do not assume that the npm name is live merely because this README
exists. From a source checkout, verify the package with:

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/cli-smoke.mjs
npm pack --dry-run
```

Node 18 or newer is required.

## Threat model

File upload validation often fails because different layers parse different
things. A browser supplies a filename and a MIME type, a server framework may
sniff a small prefix, and an image library may decode much more of the file.
Attackers exploit that gap with executable files renamed as images, polyglot
containers, active SVG or PDF content, malformed image headers, and pixel floods
that only become expensive after decoding.

`filecage` is a fail-closed boundary for the bytes your service has already
received or is about to store. It is deliberately conservative. A clean result
means the bytes passed the checks configured in your policy. It does not mean a
file is harmless in every possible viewer.

| Attack | CWE | Defense |
| --- | --- | --- |
| Executable or script uploaded with an image extension and image MIME type | CWE-434 | Magic-byte detection identifies ELF, PE, thin and universal Mach-O, Java class, WASM, and direct or obfuscated shebang content and blocks it by default. |
| MIME spoofing through a caller-controlled `Content-Type` header | CWE-434 | The claimed type is stripped of parameters and compared with the verified type. Mismatches reject the upload. |
| Extension spoofing such as `avatar.png` containing JPEG or executable bytes | CWE-434 | The filename extension is compared with the verified type using explicit alias groups. |
| RTLO right-to-left override names such as `report U+202E gnp.exe` | CWE-434 | Unicode bidi controls are rejected and removed by the sanitizer. |
| Path traversal through slash, backslash, dot, or empty filenames | CWE-22 | Path separators are never preserved. Dot aliases, empty names, controls, NUL, trailing dots, and trailing spaces are rejected by default. |
| Windows device names such as `CON`, `NUL`, `COM1`, `LPT1`, and superscript variants | CWE-22 | Reserved names are detected case-insensitively after Unicode compatibility normalization and neutralized. |
| Double-extension attacks such as `invoice.pdf.exe` or `avatar.png.php` | CWE-434 | Active final extensions after a plausible document or image extension are flagged and normalized. |
| GIFAR, JPEG plus ZIP, PNG plus PDF, and similar image document or archive polyglots | CWE-434 | Raster images are scanned for ZIP local-header and end-of-central-directory signatures plus embedded PDF and HTML/XML document signatures. Executable, zstd, OLE, and SQLite signatures are scanned only in structurally meaningful regions: PNG ancillary metadata and trailing bytes, plus trailing bytes of JPEG, WebP, and BMP images. PNG trailing bytes after IEND reject the file. Compressed PNG zTXt and iTXt metadata is inflated with strict output caps and scanned for active payloads, and inflated PNG image data is scanned for active and document signatures. If chunk limits, inflation caps, malformed chunk framing, incomplete stream consumption, or inflate errors prevent complete compressed text scanning, validation fails closed with `FILECAGE_PNG_SCAN_LIMIT`. |
| SVG script execution, event handlers, active hrefs, animated href assignment, `foreignObject`, remote `<use>` or image references, stylesheet processing instructions, and CSS network access | CWE-79 | SVG is blocked by default. Explicit opt-in still requires the active-content scan to pass. |
| SVG XML external entities and entity declarations | CWE-611 | DOCTYPE and ENTITY declarations reject the upload. |
| PDF JavaScript, launch actions, automatic actions, singular or plural embedded-file names, and URI actions | CWE-434 | PDF headers are accepted at the specification-permitted offset within the first 1024 bytes. PDF names are decoded, including hex-escaped names. Flate-compressed object streams are inflated with strict output caps and scanned. URI rejection can be configured. |
| PNG, JPEG, GIF, WebP, and BMP pixel floods and decompression bombs | CWE-400 | Width, height, and total pixels are read from binary headers and capped before any image decoder is invoked. |
| Malformed JPEG marker loops and truncated image headers | CWE-400 | The marker walker is iterative, bounded, monotonic, and rejects impossible lengths. |
| Unknown binary content | CWE-434 | Strict UTF-8 and magic-byte detection fail closed unless unknown types are explicitly enabled. |
| FIFOs, devices, sockets, directories, final-component and intermediate symlinks, executable-mode files, and oversized paths | CWE-59 / CWE-400 / CWE-434 | Path validation walks intermediate components with `lstat` using component forms that never carry a trailing separator, uses regular-file checks, `O_NOFOLLOW` and `O_NONBLOCK` where available, descriptor `fstat`, POSIX executable-mode rejection, size checks before reading, a post-read component recheck, and a post-read stability check. The root-owned macOS `/tmp` and `/var` compatibility aliases are the only permitted intermediate symlinks. |
| Terminal control and bidirectional-text injection through filenames in CLI output | CWE-117 | The CLI removes terminal control characters and Unicode bidi controls before printing names. |

## What filecage does not do

`filecage` is not a virus scanner, a sandbox, a complete PDF renderer, or a
complete XML parser. It does not execute or render content. It cannot prove that
every viewer will handle a valid file safely. Keep these additional controls in
place:

- Store uploads outside the web root and never execute them.
- Serve downloads with a strict `Content-Disposition` and a content type derived
  from the verified type, not from the original uploader.
- Re-encode user images in an isolated worker when your application can do so.
- Keep image decoding and document parsing tools patched and sandboxed.
- Use authentication, rate limits, malware scanning, and storage quotas where
  appropriate.
- Treat validation of an existing path as a read-time decision. If another
  process can replace the path after validation, do not reopen it later and
  assume the answer still applies.

PDF scanning is a security scanner, not a full PDF parser. It scans direct PDF
names and bounded Flate object streams. SVG scanning detects the dangerous
constructs listed in this README; it is not a sanitizer that makes active SVG
safe to serve inline. OOXML detection distinguishes macro-free DOCX, XLSX,
and PPTX files from macro-bearing files containing `vbaProject.bin`.

## Quick start

```js
import { validateUpload } from 'filecage';

const result = validateUpload({
  bytes: uploadedBytes,
  filename: 'avatar.png',
  contentType: 'image/png'
}, 'images-safe');

if (!result.allowed) {
  console.log(result.code);
  console.log(result.findings);
} else {
  console.log(result.safeFilename);
  console.log(result.detectedMime);
  console.log(result.dimensions);
  console.log(result.sha256);
}
```

When imported from a source checkout rather than an installed package, use a
relative path to `src/index.mjs` or `cjs/index.cjs`.

A valid PNG with honest metadata passes:

```js
import { validateUpload } from 'filecage';

const result = validateUpload({
  bytes: pngBytes,
  filename: 'avatar.png',
  contentType: 'image/png; charset=utf-8'
}, {
  preset: 'images-safe',
  maxBytes: 5 * 1024 * 1024,
  maxPixels: 12_000_000
});

if (result.allowed) {
  // Store using result.safeFilename, not the original client filename.
}
```

A renamed executable does not pass even when both metadata fields lie:

```js
const result = validateUpload({
  bytes: windowsExecutableBytes,
  filename: 'avatar.png',
  contentType: 'image/png'
}, 'images-safe');

// result.allowed is false.
// result.findings includes FILECAGE_EXECUTABLE_TYPE,
// FILECAGE_MIME_MISMATCH, and FILECAGE_EXTENSION_MISMATCH.
```

## Presets

| Preset | Verified types | Important defaults |
| --- | --- | --- |
| `images-safe` | PNG, JPEG, WebP, GIF | 10 MiB, 10000 x 10000, 25,000,000 pixels. SVG is not included. |
| `documents-safe` | PDF, plain text, CSV, JSON, DOCX, XLSX, PPTX | 25 MiB. PDF and text active-content scans remain enabled. |
| `media-safe` | MP3, MP4, QuickTime, OGG, WAV, FLAC, WebM, MKV | 100 MiB. Image dimension enforcement is not relevant to these formats. |
| `strict-custom` | None until the caller completes the policy | 4 MiB, 4096 x 4096, 8,192,000 pixels. Use with an explicit allowlist. |

A preset can be passed by name or merged with overrides:

```js
import { createUploadGuard } from 'filecage';

const guard = createUploadGuard({
  preset: 'strict-custom',
  allowedMimeTypes: ['image/png', 'image/jpeg'],
  allowedExtensions: null,
  maxBytes: 2 * 1024 * 1024
});

const result = guard.validateUpload({
  bytes,
  filename,
  contentType
});
```

If neither `allowedMimeTypes` nor `allowedExtensions` is configured, type
allowlisting is not restrictive, but executables, unknown binary data, archives,
markup, and SVG still require the relevant explicit opt-ins. Supplying either
array, even an empty array, enables allowlist enforcement. A file passes the
allowlist when either the verified MIME type or a compatible extension matches.

## Policy reference

| Option | Default | Meaning |
| --- | --- | --- |
| `allowedMimeTypes` | `null` | Verified MIME allowlist, or `null` for no MIME allowlist restriction. |
| `allowedExtensions` | `null` | Extension allowlist, or `null` for no extension allowlist restriction. |
| `maxBytes` | `10485760` | Maximum upload size. Path validation checks this before reading. |
| `maxWidth` | `10000` | Maximum parsed image width. |
| `maxHeight` | `10000` | Maximum parsed image height. |
| `maxPixels` | `25000000` | Maximum width multiplied by height. |
| `maxFilenameBytes` | `255` | UTF-8 byte cap for the storage filename. |
| `maxFindings` | `64` | Maximum reported findings. |
| `requireExtension` | `true` | Reject names without an extension. |
| `requireContentType` | `false` | Require a caller-supplied content type. It is still never trusted by itself. |
| `allowGenericContentType` | `false` | Tolerate `application/octet-stream` as non-informative metadata. |
| `allowExecutables` | `false` | Permit ELF, PE, Mach-O, Java class, WASM, shebang, macro-bearing OOXML, or executable-mode path content. Almost never enable this. |
| `allowUnknownTypes` | `false` | Permit content that cannot be identified. |
| `allowSvg` | `false` | Permit SVG after active-content scanning. |
| `allowMarkup` | `false` | Permit inert HTML or XML after active-content scanning. |
| `allowArchives` | `false` | Permit ZIP, JAR, TAR, GZIP, or ZSTD archive containers. |
| `allowPdfUri` | `false` | Do not treat a PDF `/URI` name as a finding. Other PDF actions remain blocked. |
| `scanActiveContent` | `true` | Scan for active markup, server-side tags, PDF actions, and SVG active content. |
| `scanPolyglots` | `true` | Scan raster images for ZIP signatures and trailing PNG data. |
| `enforceImageDimensions` | `true` | Require parseable PNG, JPEG, GIF, WebP, or BMP dimensions and enforce caps. |
| `canonicalizeExtension` | `true` | Make the returned storage filename end in the canonical verified extension. |
| `filenameAction` | `reject` | `reject` treats hostile filename properties as errors. `sanitize` downgrades neutralized filename findings to warnings. |

## API

### `sniffFileType(bytes)`

Returns a frozen detection result:

```js
{
  mime: 'image/png',
  ext: 'png',
  kind: 'image',
  format: 'png',
  executable: false,
  confident: true,
  signature: 'magic',
  offset: 0
}
```

Detected families include PNG, JPEG, GIF 87a and 89a, WebP, BMP, ICO, AVIF,
HEIF, TIFF little-endian and big-endian, PDF, ZIP, DOCX, XLSX, PPTX, macro-bearing
DOCM, XLSM, and PPTX, JAR, GZIP, ZSTD, TAR, MP3, MP4, QuickTime, OGG, WAV,
FLAC, WebM, Matroska, WASM, ELF, PE or DOS executables, Mach-O, Java class
files, shebang scripts, HTML, SVG, XML, strict UTF-8 plain text, JSON, and
consistent-column CSV.

### `inspectImageDimensions(bytes)`

Returns `{ format, width, height, pixels }` for PNG, JPEG, GIF, WebP, and BMP,
or `null` when the relevant binary header is malformed or unsupported. JPEG uses
an iterative marker walk for SOF0, SOF1, SOF2, SOF3, SOF5, SOF6, SOF7, SOF9,
SOF10, SOF11, SOF13, SOF14, and SOF15. No image decoder is invoked.

### `validateUpload(input, policy)`

```js
const result = validateUpload({
  bytes,
  filename,
  contentType
}, policy);
```

Returns a frozen result:

| Field | Meaning |
| --- | --- |
| `allowed` | True only when no error-severity finding exists. |
| `safeFilename` | Deterministic sanitized storage filename with canonical verified extension. |
| `detectedMime` | MIME type verified from content. |
| `detectedExt` | Canonical extension for the verified type. |
| `detectedFormat` | Internal format name such as `png`, `docx`, or `pe`. |
| `kind` | Broad family such as `image`, `document`, `media`, or `executable`. |
| `sizeBytes` | Byte size used for validation. |
| `dimensions` | Parsed image dimensions or `null`. |
| `sha256` | Lowercase SHA-256 hex digest of the inspected bytes, or `null` for truncated or unreadable input. |
| `findings` | Frozen array of frozen finding objects. |
| `code` | First error code, first warning code when there are no errors, or `null`. |

### `inspectFileBuffer(bytes, policy)`

Runs content validation without filename or content-type checks. This is useful
when bytes came from a trusted object store key rather than a multipart upload.

### `validateFilePath(filePath, policy)`

Inspects a local path using `lstat`, regular-file checks, `O_NOFOLLOW` and
`O_NONBLOCK` where the platform supports them, descriptor `fstat`, a size cap
before reading, bounded reads, and a post-read stability check. Every
intermediate directory component is checked with `lstat` before the read and
rechecked afterward. It rejects directories, final-component and intermediate
symlinks, FIFOs, devices, sockets, unstable files, oversized files, and files
with POSIX executable permission bits. On macOS only the root-owned `/tmp` and
`/var` compatibility aliases are tolerated because the system uses them for
the standard temporary directory roots. Repeated separators in a supplied path cannot
turn a component inspection into a trailing-separator symlink dereference.

The before-read and after-read component walks are consistency checks, not
descriptor-relative traversal. A local attacker who can concurrently replace
directories can still race those checks on platforms without descriptor-relative
path opening. Treat this API as a validation filter, not as protection against
an active local filesystem attacker.

### `validateWebFile(file, policy)`

Accepts a Fetch or browser `File`/`Blob`-shaped object with `arrayBuffer()` and
uses its `name`, `type`, and `size`. Reads are bounded through `stream()` when
available or through `slice(0, maxBytes + 1)` otherwise. An object with neither
interface fails closed without invoking unbounded `arrayBuffer()`. The digest
is `null` for truncated input or inconsistent oversized metadata.

### `createUploadGuard(policy)` and `createFileCage(policy)`

Return the same frozen guard object. The guard stores normalized defaults and
exposes `inspectFileBuffer`, `validateUpload`, `validateFilePath`,
`validateWebFile`, `sanitizeFilename`, and `assertSafeFilename`. Per-call
overrides do not mutate the guard policy.

### `sanitizeFilename(filename, options)`

Returns a frozen report containing `filename`, `stem`, `extension`,
`sourceExtension`, `changed`, `byteLength`, and `findings`. It strips path
components, removes controls and bidi overrides, replaces Windows-unsafe
characters, rejects dotfiles, neutralizes reserved device names and active
double extensions, enforces the UTF-8 byte cap even for very long extensions,
and never preserves a trailing dot or space.

### `assertSafeFilename(filename, options)`

Returns the same report for a clean filename and throws `FileCageError` for a
hostile one.

## Finding codes

| Code | Meaning |
| --- | --- |
| `FILECAGE_INVALID_INPUT` | Programmer or upload input shape is invalid. |
| `FILECAGE_INVALID_POLICY` | Policy contains an unknown or invalid option. |
| `FILECAGE_INVALID_UTF8` | A text or SVG security scan required valid UTF-8 and did not receive it. |
| `FILECAGE_EMPTY_FILE` | The upload has no bytes. |
| `FILECAGE_MAX_BYTES` | The upload exceeds the byte cap. |
| `FILECAGE_UNRECOGNIZED_TYPE` | Neither magic bytes nor strict text decoding identified the content. |
| `FILECAGE_TYPE_NOT_ALLOWED` | The verified type is outside the configured allowlist. |
| `FILECAGE_EXECUTABLE_TYPE` | ELF, PE, Mach-O, Java class, WASM, shebang, macro-bearing OOXML, or executable-mode path content was found. |
| `FILECAGE_ARCHIVE_NOT_ALLOWED` | An archive container requires explicit opt-in. |
| `FILECAGE_MARKUP_NOT_ALLOWED` | HTML or XML markup requires explicit opt-in. |
| `FILECAGE_SVG_NOT_ALLOWED` | SVG requires explicit opt-in. |
| `FILECAGE_CONTENT_TYPE_MISSING` | A required content type was not supplied. |
| `FILECAGE_INVALID_CONTENT_TYPE` | The supplied content type is syntactically invalid. |
| `FILECAGE_MIME_MISMATCH` | Claimed content type and verified content disagree. |
| `FILECAGE_EXTENSION_MISSING` | The filename has no extension. |
| `FILECAGE_EXTENSION_MISMATCH` | Filename extension and verified content disagree. |
| `FILECAGE_DIMENSIONS_UNREADABLE` | Image dimensions could not be verified while enforcement was enabled. |
| `FILECAGE_MAX_WIDTH` | Image width exceeds the cap. |
| `FILECAGE_MAX_HEIGHT` | Image height exceeds the cap. |
| `FILECAGE_MAX_PIXELS` | Image pixel count exceeds the cap. |
| `FILECAGE_ACTIVE_CONTENT` | Active markup or server-side code was found in file bytes. |
| `FILECAGE_POLYGLOT` | A raster image contains a ZIP, JAR, document, executable, or archive-container signature. |
| `FILECAGE_TRAILING_DATA` | A PNG contains bytes after IEND. |
| `FILECAGE_PDF_ACTIVE_CONTENT` | A PDF active action was found. |
| `FILECAGE_PDF_SCAN_LIMIT` | A compressed PDF object scan hit a safety limit or malformed stream. |
| `FILECAGE_PNG_SCAN_LIMIT` | A compressed PNG text scan hit a safety limit, malformed framing, or an inflate error before all compressed metadata was scanned. |
| `FILECAGE_SVG_ACTIVE_CONTENT` | SVG contains script, events, active hrefs, foreignObject, or remote use. |
| `FILECAGE_SVG_XXE` | SVG contains DOCTYPE or ENTITY syntax. |
| `FILECAGE_FILENAME_EMPTY` | Filename is empty. |
| `FILECAGE_FILENAME_DOT_NAME` | Filename is `.`, `..`, or a dotfile such as `.env`. |
| `FILECAGE_FILENAME_TOO_LONG` | Filename exceeds the UTF-8 byte cap. |
| `FILECAGE_FILENAME_NUL` | Filename contains NUL. |
| `FILECAGE_FILENAME_CONTROL` | Filename contains a C0, DEL, or C1 control. |
| `FILECAGE_FILENAME_BIDI` | Filename contains a Unicode bidi control. |
| `FILECAGE_FILENAME_PATH_SEPARATOR` | Filename contains slash or backslash. |
| `FILECAGE_FILENAME_UNSAFE_CHAR` | Filename contains a Windows-unsafe or separator-lookalike character. |
| `FILECAGE_FILENAME_RESERVED_DEVICE` | Filename uses a reserved Windows device name. |
| `FILECAGE_FILENAME_TRAILING_DOTS_SPACES` | Filename ends in a dot or space. |
| `FILECAGE_FILENAME_DOUBLE_EXTENSION` | Filename uses a deceptive active double extension. |
| `FILECAGE_PATH_UNSAFE` | A local path itself is unsafe. |
| `FILECAGE_PATH_SYMLINK` | A symlink was rejected. |
| `FILECAGE_PATH_NOT_REGULAR` | The path is a directory, FIFO, device, socket, or other non-regular file. |
| `FILECAGE_PATH_TOO_LARGE` | The path size exceeded the cap before reading. |
| `FILECAGE_PATH_IO_ERROR` | The path could not be opened or read safely. |
| `FILECAGE_IO_ERROR` | A web file or byte source could not be read. |
| `FILECAGE_MAX_FINDINGS` | Finding output reached the configured cap. |

## CLI

```sh
filecage inspect upload.png
filecage inspect upload.png --allow image/png,image/jpeg --json
filecage inspect large.png --max-bytes 5242880 --max-pixels 12000000
```

Exit codes:

- `0`: file passes validation.
- `1`: file is rejected or has security findings.
- `2`: usage, input, or I/O error.

The CLI validates through the same local path protections as
`validateFilePath`. JSON output is the frozen validation result serialized as
JSON.

## ESM, CommonJS, and TypeScript

```js
// ESM
import { validateUpload } from 'filecage';

// CommonJS
const { validateUpload } = require('filecage');
```

The CommonJS build is generated from `src/index.mjs` by
`scripts/build-cjs.mjs`. `node scripts/build-cjs.mjs --check` verifies that it
is current. Hand-written definitions live in `types/index.d.ts`.

## Development verification

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/cli-smoke.mjs
npm pack --dry-run
```

The test runner explicitly enumerates `tests/*.test.mjs` with `fs.readdirSync`
and invokes Node with those file paths. It does not rely on shell glob expansion,
so the same command works on Windows Node 18 and newer.
