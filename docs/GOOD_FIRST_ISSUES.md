# Good first issues

These are intentionally narrow starter specifications. Each should include
regression tests, generated CJS parity when the core changes, type updates when
the public API changes, and README updates when behavior changes.

## 1. Add JPEG2000 magic-byte detection

Detect the JPEG2000 signature box and codestream forms. Return a distinct
format, canonical extension, and image kind. Do not claim dimension support
unless header parsing is implemented and tested.

## 2. Add TIFF dimension parsing

Parse width and height tags from a bounded little-endian and big-endian TIFF
IFD walk. Reject impossible offsets, overlapping reads, zero dimensions, and
truncated tags. Include pixel-cap validation tests.

## 3. Add ICO dimension parsing

Parse the width and height bytes in the first icon directory entry. Account for
the encoded zero value meaning 256. Add malformed entry-count and truncation
tests.

## 4. Add AVIF dimension parsing research and implementation

Start with a written parser boundary in the pull request. Parse only static
metadata needed for dimensions, never compressed imagery. Reject ambiguous or
truncated boxes and add strict bounds tests.

## 5. Add OOXML external-relationship detection

Keep macro-free DOCX, XLSX, and PPTX detection while inspecting relationship
part names and bounded XML relationship content for external targets. Never
fetch those targets. Define separate findings for external links and embedded
remote objects, with strict truncation tests.

## 6. Add archive central-directory consistency checks

For ZIP family files, compare local and central entry counts where both are
available and report suspicious truncation or contradictory names. Never
decompress entries. Include fixture builders for malformed central records.

## 7. Add PDF linearization and incremental-update scan coverage

Measure whether active names can hide in common incremental-update structures.
Add bounded scanning coverage and tests without turning the scanner into a full
PDF parser.

## 8. Improve CSV strictness documentation and heuristics

Document exact CSV classification rules. Add tests for quoted delimiters,
inconsistent rows, empty rows, BOM handling, and plain-text false positives.
Keep behavior deterministic.

## 9. Add framework-free multipart example

Create a small example that shows where `validateUpload` belongs in a Node HTTP
multipart boundary, without adding a dependency or implying that the example is
a complete multipart parser.

## 10. Add Windows filename compatibility tests

Add table-driven tests for reserved names, trailing dots, trailing spaces,
superscript device variants, alternate-stream colons, and separator lookalikes.
Tests must run on every platform while asserting platform-independent output.
