/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

/** Unicode code points of PDFDocEncoding bytes 0x18-0x1F and 0x80-0xA0. */
const PDFDOC_SPECIAL: Record<number, number> = {
  0x18: 0x02d8, 0x19: 0x02c7, 0x1a: 0x02c6, 0x1b: 0x02d9, 0x1c: 0x02dd, 0x1d: 0x02db, 0x1e: 0x02da, 0x1f: 0x02dc,
  0x80: 0x2022, 0x81: 0x2020, 0x82: 0x2021, 0x83: 0x2026, 0x84: 0x2014, 0x85: 0x2013, 0x86: 0x0192, 0x87: 0x2044,
  0x88: 0x2039, 0x89: 0x203a, 0x8a: 0x2212, 0x8b: 0x2030, 0x8c: 0x201e, 0x8d: 0x201c, 0x8e: 0x201d, 0x8f: 0x2018,
  0x90: 0x2019, 0x91: 0x201a, 0x92: 0x2122, 0x93: 0xfb01, 0x94: 0xfb02, 0x95: 0x0141, 0x96: 0x0152, 0x97: 0x0160,
  0x98: 0x0178, 0x99: 0x017d, 0x9a: 0x0131, 0x9b: 0x0142, 0x9c: 0x0153, 0x9d: 0x0161, 0x9e: 0x017e, 0xa0: 0x20ac,
};
const UNICODE_TO_PDFDOC = new Map<number, number>(Object.entries(PDFDOC_SPECIAL).map(([b, u]) => [u, Number(b)]));

function toPdfDocByte(cp: number): number | null {
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return cp;
  if (cp >= 0x20 && cp <= 0x7e) return cp;
  if (cp >= 0xa1 && cp <= 0xff && cp !== 0xad) return cp;
  return UNICODE_TO_PDFDOC.get(cp) ?? null;
}

function escapeLiteral(bytes: Buffer): string {
  let out = '(';
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    if (c === '(' || c === ')' || c === '\\') out += '\\' + c;
    else if (b === 0x0a) out += '\\n';
    else if (b === 0x0d) out += '\\r';
    else out += c;
  }
  return out + ')';
}

/**
 * Text string as iText writes `PdfString(value, PdfEncodings.UNICODE_BIG)`:
 * PDFDocEncoding when every character fits, otherwise UTF-16BE with BOM.
 * Returns the serialized token (latin1).
 */
export function pdfTextString(value: string): string {
  const bytes: number[] = [];
  for (const ch of value) {
    const b = toPdfDocByte(ch.codePointAt(0)!);
    if (b === null) {
      const u = Buffer.from(value, 'utf16le');
      u.swap16();
      return '<FEFF' + u.toString('hex').toUpperCase() + '>';
    }
    bytes.push(b);
  }
  return escapeLiteral(Buffer.from(bytes));
}

/** PDF name token with #xx escapes (UTF-8 bytes, like iText). */
export function pdfName(value: string): string {
  let out = '/';
  for (const b of Buffer.from(value, 'utf8')) {
    const c = String.fromCharCode(b);
    if (b < 0x21 || b > 0x7e || '#()<>[]{}/%'.includes(c)) out += '#' + b.toString(16).padStart(2, '0');
    else out += c;
  }
  return out;
}

/** iText `PdfDate`: D:YYYYMMDDHHmmSS+HH'mm' in the given offset (minutes east of UTC). */
export function pdfDate(date: Date, offsetMinutes = -date.getTimezoneOffset()): string {
  const local = new Date(date.getTime() + offsetMinutes * 60_000);
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  let s =
    'D:' +
    p(local.getUTCFullYear(), 4) +
    p(local.getUTCMonth() + 1) +
    p(local.getUTCDate()) +
    p(local.getUTCHours()) +
    p(local.getUTCMinutes()) +
    p(local.getUTCSeconds());
  if (offsetMinutes === 0) return s + 'Z';
  const sign = offsetMinutes < 0 ? '-' : '+';
  const abs = Math.abs(offsetMinutes);
  s += sign + p(Math.floor(abs / 60)) + "'" + p(abs % 60) + "'";
  return s;
}
