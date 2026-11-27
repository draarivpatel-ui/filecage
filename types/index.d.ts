export const FILECAGE_VERSION: '1.0.0';

export const FILECAGE_ERROR_CODES: {
  readonly INVALID_INPUT: 'FILECAGE_INVALID_INPUT';
  readonly INVALID_POLICY: 'FILECAGE_INVALID_POLICY';
  readonly INVALID_UTF8: 'FILECAGE_INVALID_UTF8';
  readonly EMPTY_FILE: 'FILECAGE_EMPTY_FILE';
  readonly MAX_BYTES: 'FILECAGE_MAX_BYTES';
  readonly UNRECOGNIZED_TYPE: 'FILECAGE_UNRECOGNIZED_TYPE';
  readonly TYPE_NOT_ALLOWED: 'FILECAGE_TYPE_NOT_ALLOWED';
  readonly EXECUTABLE_TYPE: 'FILECAGE_EXECUTABLE_TYPE';
  readonly ARCHIVE_NOT_ALLOWED: 'FILECAGE_ARCHIVE_NOT_ALLOWED';
  readonly MARKUP_NOT_ALLOWED: 'FILECAGE_MARKUP_NOT_ALLOWED';
  readonly SVG_NOT_ALLOWED: 'FILECAGE_SVG_NOT_ALLOWED';
  readonly CONTENT_TYPE_MISSING: 'FILECAGE_CONTENT_TYPE_MISSING';
  readonly INVALID_CONTENT_TYPE: 'FILECAGE_INVALID_CONTENT_TYPE';
  readonly MIME_MISMATCH: 'FILECAGE_MIME_MISMATCH';
  readonly EXTENSION_MISSING: 'FILECAGE_EXTENSION_MISSING';
  readonly EXTENSION_MISMATCH: 'FILECAGE_EXTENSION_MISMATCH';
  readonly DIMENSIONS_UNREADABLE: 'FILECAGE_DIMENSIONS_UNREADABLE';
  readonly MAX_WIDTH: 'FILECAGE_MAX_WIDTH';
  readonly MAX_HEIGHT: 'FILECAGE_MAX_HEIGHT';
  readonly MAX_PIXELS: 'FILECAGE_MAX_PIXELS';
  readonly ACTIVE_CONTENT: 'FILECAGE_ACTIVE_CONTENT';
  readonly POLYGLOT: 'FILECAGE_POLYGLOT';
  readonly TRAILING_DATA: 'FILECAGE_TRAILING_DATA';
  readonly PDF_ACTIVE_CONTENT: 'FILECAGE_PDF_ACTIVE_CONTENT';
  readonly PDF_SCAN_LIMIT: 'FILECAGE_PDF_SCAN_LIMIT';
  readonly SVG_ACTIVE_CONTENT: 'FILECAGE_SVG_ACTIVE_CONTENT';
  readonly SVG_XXE: 'FILECAGE_SVG_XXE';
  readonly FILENAME_EMPTY: 'FILECAGE_FILENAME_EMPTY';
  readonly FILENAME_DOT_NAME: 'FILECAGE_FILENAME_DOT_NAME';
  readonly FILENAME_TOO_LONG: 'FILECAGE_FILENAME_TOO_LONG';
  readonly FILENAME_NUL: 'FILECAGE_FILENAME_NUL';
  readonly FILENAME_CONTROL: 'FILECAGE_FILENAME_CONTROL';
  readonly FILENAME_BIDI: 'FILECAGE_FILENAME_BIDI';
  readonly FILENAME_PATH_SEPARATOR: 'FILECAGE_FILENAME_PATH_SEPARATOR';
  readonly FILENAME_UNSAFE_CHAR: 'FILECAGE_FILENAME_UNSAFE_CHAR';
  readonly FILENAME_RESERVED_DEVICE: 'FILECAGE_FILENAME_RESERVED_DEVICE';
  readonly FILENAME_TRAILING_DOTS_SPACES: 'FILECAGE_FILENAME_TRAILING_DOTS_SPACES';
  readonly FILENAME_DOUBLE_EXTENSION: 'FILECAGE_FILENAME_DOUBLE_EXTENSION';
  readonly PATH_UNSAFE: 'FILECAGE_PATH_UNSAFE';
  readonly PATH_SYMLINK: 'FILECAGE_PATH_SYMLINK';
  readonly PATH_NOT_REGULAR: 'FILECAGE_PATH_NOT_REGULAR';
  readonly PATH_TOO_LARGE: 'FILECAGE_PATH_TOO_LARGE';
  readonly PATH_IO_ERROR: 'FILECAGE_PATH_IO_ERROR';
  readonly IO_ERROR: 'FILECAGE_IO_ERROR';
  readonly MAX_FINDINGS: 'FILECAGE_MAX_FINDINGS';
};

export const CODE: typeof FILECAGE_ERROR_CODES;

export type FileCageErrorCode = typeof FILECAGE_ERROR_CODES[keyof typeof FILECAGE_ERROR_CODES];

export class FileCageError extends Error {
  constructor(code: FileCageErrorCode | string, message: string, details?: Record<string, unknown>);
  readonly code: FileCageErrorCode | string;
  readonly reason: string;
  readonly position?: number;
  readonly pattern?: string;
  readonly token?: string;
  readonly limit?: number;
  readonly actual?: number | string;
  readonly width?: number;
  readonly height?: number;
  readonly pixels?: number;
  readonly filename?: string;
  readonly extension?: string;
  readonly mime?: string;
  readonly key?: string;
  toJSON(): Record<string, unknown>;
}

export type FileCageBytes = Uint8Array | ArrayBuffer | SharedArrayBuffer | ArrayBufferView;

export interface FileCageSniffResult {
  readonly mime: string;
  readonly ext: string;
  readonly kind: 'image' | 'document' | 'media' | 'archive' | 'executable' | 'markup' | 'text' | 'data' | 'binary';
  readonly format: string;
  readonly executable: boolean;
  readonly confident: boolean;
  readonly signature: string;
  readonly offset: number;
}

export interface FileCageImageDimensions {
  readonly format: 'png' | 'jpeg' | 'gif' | 'webp' | 'bmp';
  readonly width: number;
  readonly height: number;
  readonly pixels: number;
}

export type FileCagePresetName = 'images-safe' | 'documents-safe' | 'media-safe' | 'strict-custom';

export interface FileCagePolicy {
  preset?: FileCagePresetName;
  allowedMimeTypes?: readonly string[] | null;
  allowedExtensions?: readonly string[] | null;
  maxBytes?: number;
  maxWidth?: number;
  maxHeight?: number;
  maxPixels?: number;
  maxFilenameBytes?: number;
  maxFindings?: number;
  requireExtension?: boolean;
  requireContentType?: boolean;
  allowGenericContentType?: boolean;
  allowExecutables?: boolean;
  allowUnknownTypes?: boolean;
  allowSvg?: boolean;
  allowMarkup?: boolean;
  allowArchives?: boolean;
  allowPdfUri?: boolean;
  scanActiveContent?: boolean;
  scanPolyglots?: boolean;
  enforceImageDimensions?: boolean;
  canonicalizeExtension?: boolean;
  filenameAction?: 'reject' | 'sanitize';
}

export type FileCagePolicyInput = FileCagePolicy | FileCagePresetName;

export const FILECAGE_PRESETS: {
  readonly 'images-safe': Readonly<FileCagePolicy>;
  readonly 'documents-safe': Readonly<FileCagePolicy>;
  readonly 'media-safe': Readonly<FileCagePolicy>;
  readonly 'strict-custom': Readonly<FileCagePolicy>;
};

export interface FileCageFinding {
  readonly code: FileCageErrorCode;
  readonly message: string;
  readonly severity: 'error' | 'warning';
  readonly position?: number;
  readonly pattern?: string;
  readonly token?: string;
  readonly limit?: number;
  readonly actual?: number | string;
  readonly width?: number;
  readonly height?: number;
  readonly pixels?: number;
  readonly extension?: string;
  readonly mime?: string;
}

export interface FileCageValidationResult {
  readonly allowed: boolean;
  readonly safeFilename: string | null;
  readonly detectedMime: string | null;
  readonly detectedExt: string | null;
  readonly detectedFormat: string | null;
  readonly kind: string | null;
  readonly sizeBytes: number | null;
  readonly dimensions: FileCageImageDimensions | null;
  readonly sha256: string | null;
  readonly findings: readonly FileCageFinding[];
  readonly code: FileCageErrorCode | null;
}

export interface FileCageUploadInput {
  readonly bytes: FileCageBytes;
  readonly filename: string;
  readonly contentType?: string | null;
}

export interface FileCageFilenameOptions {
  readonly maxBytes?: number;
}

export interface FileCageFilenameReport {
  readonly original: string;
  readonly filename: string;
  readonly stem: string;
  readonly extension: string;
  readonly sourceExtension: string;
  readonly changed: boolean;
  readonly byteLength: number;
  readonly findings: readonly FileCageFinding[];
}

export interface FileCageWebFile {
  readonly size?: number;
  readonly type?: string;
  readonly name?: string;
  arrayBuffer(): Promise<ArrayBuffer>;
  slice?(start?: number, end?: number): FileCageWebFile;
}

export interface FileCageGuard {
  readonly policy: Readonly<FileCagePolicy>;
  inspectFileBuffer(bytes: FileCageBytes, overrides?: FileCagePolicyInput): FileCageValidationResult;
  validateUpload(input: FileCageUploadInput, overrides?: FileCagePolicyInput): FileCageValidationResult;
  validateFilePath(filePath: string, overrides?: FileCagePolicyInput): FileCageValidationResult;
  validateWebFile(file: FileCageWebFile, overrides?: FileCagePolicyInput): Promise<FileCageValidationResult>;
  sanitizeFilename(filename: string, options?: FileCageFilenameOptions): FileCageFilenameReport;
  assertSafeFilename(filename: string, options?: FileCageFilenameOptions): FileCageFilenameReport;
}

export function sniffFileType(bytes: FileCageBytes): FileCageSniffResult;
export function inspectImageDimensions(bytes: FileCageBytes): FileCageImageDimensions | null;
export function inspectFileBuffer(bytes: FileCageBytes, policy?: FileCagePolicyInput): FileCageValidationResult;
export function validateUpload(input: FileCageUploadInput, policy?: FileCagePolicyInput): FileCageValidationResult;
export function validateFilePath(filePath: string, policy?: FileCagePolicyInput): FileCageValidationResult;
export function validateWebFile(file: FileCageWebFile, policy?: FileCagePolicyInput): Promise<FileCageValidationResult>;
export function createUploadGuard(policy?: FileCagePolicyInput): FileCageGuard;
export function createFileCage(policy?: FileCagePolicyInput): FileCageGuard;
export function sanitizeFilename(filename: string, options?: FileCageFilenameOptions): FileCageFilenameReport;
export function assertSafeFilename(filename: string, options?: FileCageFilenameOptions): FileCageFilenameReport;

declare const filecage: {
  readonly FILECAGE_VERSION: typeof FILECAGE_VERSION;
  readonly FILECAGE_ERROR_CODES: typeof FILECAGE_ERROR_CODES;
  readonly CODE: typeof CODE;
  readonly FILECAGE_PRESETS: typeof FILECAGE_PRESETS;
  readonly FileCageError: typeof FileCageError;
  readonly sniffFileType: typeof sniffFileType;
  readonly inspectImageDimensions: typeof inspectImageDimensions;
  readonly inspectFileBuffer: typeof inspectFileBuffer;
  readonly validateUpload: typeof validateUpload;
  readonly validateFilePath: typeof validateFilePath;
  readonly validateWebFile: typeof validateWebFile;
  readonly createUploadGuard: typeof createUploadGuard;
  readonly createFileCage: typeof createFileCage;
  readonly sanitizeFilename: typeof sanitizeFilename;
  readonly assertSafeFilename: typeof assertSafeFilename;
};

export default filecage;
