import assert from 'node:assert/strict';
import test from 'node:test';
import { parseCsv, stringifyCsv } from '../src/csv.js';

test('CSV parser handles BOM, quoted commas, escaped quotes, and CRLF', () => {
  const rows = parseCsv('\uFEFFid,name,notes\r\na,"quoted, name","a ""quote"""\r\n');
  assert.deepEqual(rows, [{ id: 'a', name: 'quoted, name', notes: 'a "quote"' }]);
});

test('CSV parser rejects malformed and resource-exhausting input', () => {
  assert.throws(() => parseCsv('a,b\n"unterminated,b\n'), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => parseCsv('a,b\n1,2\n3,4\n', { maxRows: 1 }), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => parseCsv('a,a\n1,2\n'), (error) => error.code === 'INVALID_CSV');
});

test('CSV stringifier escapes commas, quotes, newlines, empty values, and Unicode and round-trips with parseCsv', () => {
  const headers = ['sample_id', 'name', 'notes', 'empty_cell'];
  const objectRows = [
    {
      sample_id: 'RWB-001',
      name: 'Extension, "Quoted"',
      notes: 'Line 1\nLine 2\r\nTiếng Việt — 日本語 🔐',
      empty_cell: ''
    },
    {
      sample_id: 'RWB-002',
      name: null,
      notes: undefined,
      empty_cell: 0
    }
  ];
  const csvFromObjects = stringifyCsv(headers, objectRows);
  assert.equal(
    csvFromObjects,
    'sample_id,name,notes,empty_cell\n'
    + 'RWB-001,"Extension, ""Quoted""","Line 1\nLine 2\r\nTiếng Việt — 日本語 🔐",\n'
    + 'RWB-002,,,0\n'
  );
  assert.deepEqual(parseCsv(csvFromObjects), [
    {
      sample_id: 'RWB-001',
      name: 'Extension, "Quoted"',
      notes: 'Line 1\nLine 2\r\nTiếng Việt — 日本語 🔐',
      empty_cell: ''
    },
    {
      sample_id: 'RWB-002',
      name: '',
      notes: '',
      empty_cell: '0'
    }
  ]);

  const arrayRows = [
    ['CST-001', 'Plain', 'a,b', ''],
    ['CST-002', '"quoted"', 'line\nbreak', null]
  ];
  const csvFromArrays = stringifyCsv(headers, arrayRows);
  assert.deepEqual(parseCsv(csvFromArrays), [
    { sample_id: 'CST-001', name: 'Plain', notes: 'a,b', empty_cell: '' },
    { sample_id: 'CST-002', name: '"quoted"', notes: 'line\nbreak', empty_cell: '' }
  ]);
});

test('CSV stringifier rejects invalid headers and malformed rows', () => {
  assert.throws(() => stringifyCsv([], []), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => stringifyCsv(['a', 'a'], []), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => stringifyCsv(['a', ''], []), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => stringifyCsv(['a', 'b'], 'not-array'), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => stringifyCsv(['a', 'b'], [['only-one']]), (error) => error.code === 'INVALID_CSV');
  assert.throws(() => stringifyCsv(['a', 'b'], ['bad-row']), (error) => error.code === 'INVALID_CSV');
});
