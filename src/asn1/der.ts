/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

/**
 * Minimal DER reader/writer. Nodes keep their raw encoding so values can be
 * re-emitted byte for byte (needed to mimic Java/BouncyCastle "#hex" output).
 */

export const TagClass = {
  UNIVERSAL: 0,
  APPLICATION: 1,
  CONTEXT: 2,
  PRIVATE: 3,
} as const;

export const Tag = {
  BOOLEAN: 1,
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  UTF8_STRING: 12,
  SEQUENCE: 16,
  SET: 17,
  NUMERIC_STRING: 18,
  PRINTABLE_STRING: 19,
  T61_STRING: 20,
  VIDEOTEX_STRING: 21,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  GRAPHIC_STRING: 25,
  VISIBLE_STRING: 26,
  GENERAL_STRING: 27,
  UNIVERSAL_STRING: 28,
  BMP_STRING: 30,
} as const;

export interface DerNode {
  tagClass: number;
  constructed: boolean;
  tag: number;
  /** Content octets. */
  value: Buffer;
  /** Full TLV encoding. */
  raw: Buffer;
  /** Parsed children when constructed. */
  children: DerNode[];
}

export function parseDer(input: Uint8Array, strict = true): DerNode {
  const buf = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const [node, end] = readNode(buf, 0);
  if (strict && end !== buf.length) {
    throw new Error(`DER: ${buf.length - end} bytes sobrantes`);
  }
  return node;
}

/** Parses a DER value at the start of the buffer, ignoring trailing bytes. */
export function parseDerPrefix(input: Uint8Array): DerNode {
  return parseDer(input, false);
}

function readNode(buf: Buffer, offset: number): [DerNode, number] {
  const start = offset;
  if (offset >= buf.length) throw new Error('DER: fin inesperado');
  const first = buf[offset++];
  const tagClass = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    let b: number;
    do {
      if (offset >= buf.length) throw new Error('DER: tag truncado');
      b = buf[offset++];
      tag = tag * 128 + (b & 0x7f);
    } while (b & 0x80);
  }
  if (offset >= buf.length) throw new Error('DER: longitud truncada');
  let len = buf[offset++];
  let indefinite = false;
  if (len === 0x80) {
    indefinite = true;
    len = 0;
  } else if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 6 || offset + n > buf.length) throw new Error('DER: longitud invalida');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[offset++];
  }
  const children: DerNode[] = [];
  if (indefinite) {
    // BER indefinite length: read children until end-of-contents.
    if (!constructed) throw new Error('DER: longitud indefinida en primitivo');
    const contentStart = offset;
    while (!(buf[offset] === 0 && buf[offset + 1] === 0)) {
      const [child, next] = readNode(buf, offset);
      children.push(child);
      offset = next;
    }
    const value = buf.subarray(contentStart, offset);
    offset += 2;
    return [{ tagClass, constructed, tag, value, raw: buf.subarray(start, offset), children }, offset];
  }
  const end = offset + len;
  if (end > buf.length) throw new Error('DER: contenido truncado');
  const value = buf.subarray(offset, end);
  if (constructed) {
    let p = offset;
    while (p < end) {
      const [child, next] = readNode(buf, p);
      children.push(child);
      p = next;
    }
  }
  return [{ tagClass, constructed, tag, value, raw: buf.subarray(start, end), children }, end];
}

export function isUniversal(node: DerNode, tag: number): boolean {
  return node.tagClass === TagClass.UNIVERSAL && node.tag === tag;
}

export function isContext(node: DerNode, tag: number): boolean {
  return node.tagClass === TagClass.CONTEXT && node.tag === tag;
}

export function decodeOid(value: Buffer): string {
  const parts: number[] = [];
  let acc = 0;
  for (let i = 0; i < value.length; i++) {
    acc = acc * 128 + (value[i] & 0x7f);
    if (!(value[i] & 0x80)) {
      if (parts.length === 0) {
        if (acc < 40) parts.push(0, acc);
        else if (acc < 80) parts.push(1, acc - 40);
        else parts.push(2, acc - 80);
      } else {
        parts.push(acc);
      }
      acc = 0;
    }
  }
  return parts.join('.');
}

export function decodeInteger(value: Buffer): bigint {
  if (value.length === 0) return 0n;
  let n = BigInt('0x' + value.toString('hex'));
  if (value[0] & 0x80) n -= 1n << BigInt(value.length * 8);
  return n;
}

export function decodeTime(node: DerNode): Date {
  const s = node.value.toString('latin1');
  if (isUniversal(node, Tag.UTC_TIME)) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
    if (!m) throw new Error('UTCTime invalido: ' + s);
    const yy = parseInt(m[1], 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], m[6] ? +m[6] : 0));
  }
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?Z$/.exec(s);
  if (!m) throw new Error('GeneralizedTime invalido: ' + s);
  const ms = m[7] ? Math.round(parseFloat('0.' + m[7]) * 1000) : 0;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], m[6] ? +m[6] : 0, ms));
}

// ---------------------------------------------------------------- writer

function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  while (len > 0) {
    bytes.unshift(len & 0xff);
    len = Math.floor(len / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeTag(tagClass: number, constructed: boolean, tag: number): Buffer {
  const first = (tagClass << 6) | (constructed ? 0x20 : 0);
  if (tag < 0x1f) return Buffer.from([first | tag]);
  const bytes: number[] = [tag & 0x7f];
  tag = Math.floor(tag / 128);
  while (tag > 0) {
    bytes.unshift(0x80 | (tag & 0x7f));
    tag = Math.floor(tag / 128);
  }
  return Buffer.from([first | 0x1f, ...bytes]);
}

export function tlv(tagClass: number, constructed: boolean, tag: number, content: Uint8Array): Buffer {
  return Buffer.concat([encodeTag(tagClass, constructed, tag), encodeLength(content.length), content]);
}

export const der = {
  sequence: (...items: Uint8Array[]) => tlv(TagClass.UNIVERSAL, true, Tag.SEQUENCE, Buffer.concat(items)),
  /** DER SET OF: elements sorted by their encoding. */
  set: (...items: Uint8Array[]) =>
    tlv(TagClass.UNIVERSAL, true, Tag.SET, Buffer.concat([...items].map((i) => Buffer.from(i)).sort(Buffer.compare))),
  /** SET keeping the given order (for already-ordered content). */
  setUnsorted: (...items: Uint8Array[]) => tlv(TagClass.UNIVERSAL, true, Tag.SET, Buffer.concat(items)),
  explicit: (n: number, ...items: Uint8Array[]) => tlv(TagClass.CONTEXT, true, n, Buffer.concat(items)),
  implicitConstructed: (n: number, content: Uint8Array) => tlv(TagClass.CONTEXT, true, n, content),
  implicitPrimitive: (n: number, content: Uint8Array) => tlv(TagClass.CONTEXT, false, n, content),
  null: () => Buffer.from([0x05, 0x00]),
  bool: (v: boolean) => tlv(TagClass.UNIVERSAL, false, Tag.BOOLEAN, Buffer.from([v ? 0xff : 0x00])),
  octetString: (v: Uint8Array) => tlv(TagClass.UNIVERSAL, false, Tag.OCTET_STRING, v),
  bitString: (v: Uint8Array, unused = 0) =>
    tlv(TagClass.UNIVERSAL, false, Tag.BIT_STRING, Buffer.concat([Buffer.from([unused]), v])),
  utf8: (s: string) => tlv(TagClass.UNIVERSAL, false, Tag.UTF8_STRING, Buffer.from(s, 'utf8')),
  printable: (s: string) => tlv(TagClass.UNIVERSAL, false, Tag.PRINTABLE_STRING, Buffer.from(s, 'latin1')),
  ia5: (s: string) => tlv(TagClass.UNIVERSAL, false, Tag.IA5_STRING, Buffer.from(s, 'latin1')),
  integer: (n: bigint | number) => tlv(TagClass.UNIVERSAL, false, Tag.INTEGER, integerBytes(BigInt(n))),
  integerRaw: (bytes: Uint8Array) => tlv(TagClass.UNIVERSAL, false, Tag.INTEGER, bytes),
  oid: (oid: string) => tlv(TagClass.UNIVERSAL, false, Tag.OID, oidBytes(oid)),
  utcTime: (d: Date) => tlv(TagClass.UNIVERSAL, false, Tag.UTC_TIME, Buffer.from(formatTime(d, true), 'latin1')),
  generalizedTime: (d: Date) =>
    tlv(TagClass.UNIVERSAL, false, Tag.GENERALIZED_TIME, Buffer.from(formatTime(d, false), 'latin1')),
};

function formatTime(d: Date, utc: boolean): string {
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  const y = d.getUTCFullYear();
  const body =
    p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds());
  return (utc ? p(y % 100) : p(y, 4)) + body + 'Z';
}

export function integerBytes(n: bigint): Buffer {
  if (n === 0n) return Buffer.from([0]);
  if (n < 0n) {
    let bytes = 1;
    while (n < -(1n << BigInt(bytes * 8 - 1))) bytes++;
    const v = (1n << BigInt(bytes * 8)) + n;
    return Buffer.from(v.toString(16).padStart(bytes * 2, '0'), 'hex');
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const b = Buffer.from(hex, 'hex');
  return b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b;
}

export function oidBytes(oid: string): Buffer {
  const parts = oid.split('.').map((p) => BigInt(p));
  if (parts.length < 2) throw new Error('OID invalido: ' + oid);
  const out: number[] = [];
  const push = (v: bigint) => {
    const tmp: number[] = [Number(v & 0x7fn)];
    v >>= 7n;
    while (v > 0n) {
      tmp.unshift(Number(v & 0x7fn) | 0x80);
      v >>= 7n;
    }
    out.push(...tmp);
  };
  push(parts[0] * 40n + parts[1]);
  for (let i = 2; i < parts.length; i++) push(parts[i]);
  return Buffer.from(out);
}
