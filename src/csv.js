import { MvxError } from './errors.js';

const DEFAULT_LIMITS = Object.freeze({ maxRows: 20_000, maxColumns: 128, maxCellBytes: 1_000_000 });

export function parseCsv(source, options = {}) {
  if (typeof source !== 'string') throw new MvxError('CSV input must be text', { code: 'INVALID_CSV' });
  const limits = { ...DEFAULT_LIMITS, ...options };
  const text = source.replace(/^\uFEFF/, '');
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  const append = (value) => {
    field += value;
    if (Buffer.byteLength(field) > limits.maxCellBytes) {
      throw new MvxError(`CSV cell exceeds ${limits.maxCellBytes} bytes`, { code: 'INVALID_CSV' });
    }
  };
  const endField = () => {
    row.push(field);
    field = '';
    if (row.length > limits.maxColumns) {
      throw new MvxError(`CSV row exceeds ${limits.maxColumns} columns`, { code: 'INVALID_CSV' });
    }
  };
  const endRow = () => {
    endField();
    rows.push(row);
    row = [];
    if (rows.length > limits.maxRows + 1) {
      throw new MvxError(`CSV exceeds ${limits.maxRows} data rows`, { code: 'INVALID_CSV' });
    }
  };

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        append('"');
        index += 1;
      } else if (character === '"') quoted = false;
      else append(character);
      continue;
    }
    if (character === '"') {
      if (field.length > 0) throw new MvxError('Unexpected quote in unquoted CSV cell', { code: 'INVALID_CSV' });
      quoted = true;
    } else if (character === ',') endField();
    else if (character === '\n') endRow();
    else if (character === '\r' && text[index + 1] === '\n') {
      endRow();
      index += 1;
    } else if (character === '\r') endRow();
    else append(character);
  }
  if (quoted) throw new MvxError('Unterminated quoted CSV cell', { code: 'INVALID_CSV' });
  if (field.length > 0 || row.length > 0) endRow();
  while (rows.length > 0 && rows.at(-1).every((value) => value === '')) rows.pop();
  if (rows.length === 0) return [];

  const headers = rows.shift();
  if (headers.some((header) => header.length === 0) || new Set(headers).size !== headers.length) {
    throw new MvxError('CSV headers must be non-empty and unique', { code: 'INVALID_CSV' });
  }
  return rows.map((values, index) => {
    if (values.length !== headers.length) {
      throw new MvxError(`CSV row ${index + 2} has ${values.length} columns; expected ${headers.length}`, { code: 'INVALID_CSV' });
    }
    return Object.fromEntries(headers.map((header, column) => [header, values[column]]));
  });
}

function escapeCsvCell(value) {
  if (value === null || value === undefined) return '';
  const text = String(value);
  if (/[",\r\n]/.test(text)) {
    return `"${text.replaceAll('"', '""')}"`;
  }
  return text;
}

export function stringifyCsv(headers, rows = []) {
  if (!Array.isArray(headers) || headers.length === 0
    || headers.some((header) => typeof header !== 'string' || header.length === 0)
    || new Set(headers).size !== headers.length) {
    throw new MvxError('CSV headers must be a non-empty array of unique non-empty strings', { code: 'INVALID_CSV' });
  }
  if (!Array.isArray(rows)) {
    throw new MvxError('CSV rows must be an array', { code: 'INVALID_CSV' });
  }
  const lines = [headers.map(escapeCsvCell).join(',')];
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    let values;
    if (Array.isArray(row)) {
      if (row.length !== headers.length) {
        throw new MvxError(`CSV row ${index + 2} has ${row.length} columns; expected ${headers.length}`, { code: 'INVALID_CSV' });
      }
      values = row;
    } else if (row && typeof row === 'object') {
      values = headers.map((header) => (Object.hasOwn(row, header) ? row[header] : ''));
    } else {
      throw new MvxError(`CSV row ${index + 2} must be an array or object`, { code: 'INVALID_CSV' });
    }
    lines.push(values.map(escapeCsvCell).join(','));
  }
  return `${lines.join('\n')}\n`;
}
