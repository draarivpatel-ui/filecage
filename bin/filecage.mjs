#!/usr/bin/env node
import { validateFilePath, FILECAGE_VERSION } from '../src/index.mjs';

function neutralizeTerminal(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, '');
}

function usage() {
  return [
    'filecage ' + FILECAGE_VERSION,
    '',
    'Usage:',
    '  filecage inspect <file> [--allow <mime1,mime2>] [--max-bytes N] [--max-pixels N] [--json]',
    '',
    'Exit codes:',
    '  0  file passes validation',
    '  1  file is rejected or has security findings',
    '  2  usage, input, or I/O error'
  ].join('\n');
}

function parsePositiveInteger(value, flag) {
  if (!/^[0-9]+$/.test(value)) throw new Error(flag + ' requires a positive integer');
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) throw new Error(flag + ' requires a positive integer');
  return number;
}

function parseArgs(args) {
  if (args.length === 0) throw new Error('missing command');
  if (args.includes('--help') || args.includes('-h')) return { help: true };
  if (args.length === 1 && (args[0] === '--version' || args[0] === '-v')) return { version: true };
  const [command, ...rest] = args;
  if (command !== 'inspect') throw new Error('expected the inspect command');
  const output = {
    file: null,
    allow: [],
    maxBytes: undefined,
    maxPixels: undefined,
    json: false
  };
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === '--json') {
      output.json = true;
    } else if (arg === '--allow' || arg === '--max-bytes' || arg === '--max-pixels') {
      index += 1;
      if (index >= rest.length) throw new Error(arg + ' requires a value');
      const value = rest[index];
      if (arg === '--allow') {
        for (const mime of value.split(',')) {
          const normalized = mime.trim().toLowerCase();
          if (normalized) output.allow.push(normalized);
        }
      } else if (arg === '--max-bytes') {
        output.maxBytes = parsePositiveInteger(value, arg);
      } else {
        output.maxPixels = parsePositiveInteger(value, arg);
      }
    } else if (arg.startsWith('--')) {
      throw new Error('unknown option ' + neutralizeTerminal(arg));
    } else if (output.file === null) {
      output.file = arg;
    } else {
      throw new Error('inspect accepts exactly one file');
    }
  }
  if (output.file === null) throw new Error('inspect requires a file');
  return output;
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error('filecage: ' + neutralizeTerminal(error.message));
    console.error(usage());
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    console.log(usage());
    return;
  }
  if (options.version) {
    console.log(FILECAGE_VERSION);
    return;
  }

  const policy = {
    allowedMimeTypes: options.allow.length > 0 ? options.allow : null,
    maxBytes: options.maxBytes,
    maxPixels: options.maxPixels
  };
  let result;
  try {
    result = validateFilePath(options.file, policy);
  } catch (error) {
    console.error('filecage: ' + neutralizeTerminal(error.message));
    process.exitCode = 2;
    return;
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log('filecage: ' + (result.allowed ? 'safe' : 'rejected'));
    console.log('file: ' + neutralizeTerminal(result.safeFilename || 'unknown'));
    console.log('type: ' + neutralizeTerminal(result.detectedMime || 'unverified'));
    console.log('size: ' + String(result.sizeBytes === null ? 'unknown' : result.sizeBytes) + ' bytes');
    if (result.dimensions) {
      console.log('dimensions: ' + result.dimensions.width + 'x' + result.dimensions.height);
    }
    for (const item of result.findings) {
      console.log(item.severity + ': ' + item.code + ': ' + neutralizeTerminal(item.message));
    }
    if (result.findings.length === 0) console.log('findings: none');
  }

  const ioFailure = result.findings.some((item) => item.code === 'FILECAGE_PATH_IO_ERROR' || item.code === 'FILECAGE_PATH_UNSAFE');
  process.exitCode = result.allowed ? 0 : (ioFailure ? 2 : 1);
}

main().catch((error) => {
  console.error('filecage: ' + neutralizeTerminal(error && error.message ? error.message : 'unexpected failure'));
  process.exitCode = 2;
});
