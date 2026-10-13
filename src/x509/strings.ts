/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import { DerNode, Tag, TagClass, decodeInteger, decodeOid, isUniversal, parseDer } from '../asn1/der.js';

/**
 * String semantics of the two Java stacks the original library mixes:
 *  - BouncyCastle (`ASN1String.getString`, `IETFUtils.valueToString`, `toString`)
 *  - the JDK (`DerValue.getAsString`, used by `X500Principal.toString`)
 */

function latin1(b: Buffer): string {
  return b.toString('latin1');
}

function utf16be(b: Buffer): string {
  const swapped = Buffer.from(b);
  if (swapped.length % 2) return new TextDecoder('utf-16be').decode(b);
  swapped.swap16();
  return swapped.toString('utf16le');
}

function utf32be(b: Buffer): string {
  let s = '';
  for (let i = 0; i + 3 < b.length; i += 4) {
    const cp = b.readUInt32BE(i);
    s += cp <= 0x10ffff ? String.fromCodePoint(cp) : '�';
  }
  return s;
}

function ascii(b: Buffer): string {
  let s = '';
  for (const byte of b) s += byte < 0x80 ? String.fromCharCode(byte) : '�';
  return s;
}

const BC_STRING_TAGS = new Set<number>([
  Tag.UTF8_STRING,
  Tag.NUMERIC_STRING,
  Tag.PRINTABLE_STRING,
  Tag.T61_STRING,
  Tag.VIDEOTEX_STRING,
  Tag.IA5_STRING,
  Tag.GRAPHIC_STRING,
  Tag.VISIBLE_STRING,
  Tag.GENERAL_STRING,
  Tag.UNIVERSAL_STRING,
  Tag.BMP_STRING,
  Tag.BIT_STRING,
]);

/** True when BouncyCastle would parse this node as an `ASN1String`. */
export function isBcAsn1String(node: DerNode): boolean {
  return node.tagClass === TagClass.UNIVERSAL && !node.constructed && BC_STRING_TAGS.has(node.tag);
}

/** BouncyCastle `ASN1String.getString()`. */
export function bcGetString(node: DerNode): string {
  switch (node.tag) {
    case Tag.UTF8_STRING:
      return node.value.toString('utf8');
    case Tag.BMP_STRING:
      return utf16be(node.value);
    case Tag.UNIVERSAL_STRING:
    case Tag.BIT_STRING:
      return '#' + node.raw.toString('hex').toUpperCase();
    default:
      return latin1(node.value);
  }
}

/** BouncyCastle `IETFUtils.valueToString(ASN1Encodable)`. */
export function bcValueToString(node: DerNode): string {
  let v: string;
  if (isBcAsn1String(node) && node.tag !== Tag.UNIVERSAL_STRING) {
    const s = bcGetString(node);
    v = (s.length > 0 && s[0] === '#' ? '\\' : '') + s;
  } else {
    v = '#' + node.raw.toString('hex');
  }
  const chars = [...v];
  const out: string[] = [];
  let i = 0;
  if (chars.length >= 2 && chars[0] === '\\' && chars[1] === '#') {
    out.push('\\', '#');
    i = 2;
  }
  for (; i < chars.length; i++) {
    const c = chars[i];
    if (',"\\+=<>;'.includes(c)) out.push('\\');
    out.push(c);
  }
  let s = out.join('');
  // escape leading and trailing spaces
  let start = 0;
  while (start < s.length && s[start] === ' ') {
    s = s.slice(0, start) + '\\' + s.slice(start);
    start += 2;
  }
  let end = s.length - 1;
  while (end >= 0 && s[end] === ' ') {
    s = s.slice(0, end) + '\\' + s.slice(end);
    end--;
  }
  return s;
}

/** BouncyCastle `ASN1Primitive.toString()` for the common types. */
export function bcToString(node: DerNode): string {
  if (node.tagClass === TagClass.UNIVERSAL) {
    if (isBcAsn1String(node)) return bcGetString(node);
    switch (node.tag) {
      case Tag.INTEGER:
        return decodeInteger(node.value).toString();
      case Tag.OID:
        return decodeOid(node.value);
      case Tag.OCTET_STRING:
        return '#' + node.value.toString('hex');
      case Tag.NULL:
        return 'NULL';
      case Tag.BOOLEAN:
        return node.value[0] ? 'TRUE' : 'FALSE';
      case Tag.UTC_TIME:
      case Tag.GENERALIZED_TIME:
        return latin1(node.value);
      case Tag.SEQUENCE:
      case Tag.SET:
        return '[' + node.children.map(bcToString).join(', ') + ']';
    }
    return '#' + node.raw.toString('hex');
  }
  const cls = ['UNIVERSAL', 'APPLICATION', 'CONTEXT', 'PRIVATE'][node.tagClass];
  if (node.constructed) {
    // explicit tagging: a single inner object
    if (node.children.length === 1) return `[${cls} ${node.tag}]` + bcToString(node.children[0]);
    return `[${cls} ${node.tag}]` + '[' + node.children.map(bcToString).join(', ') + ']';
  }
  return `[${cls} ${node.tag}]` + '#' + node.value.toString('hex');
}

/** JDK `DerValue.getAsString()`; null for non string types. */
export function jdkGetAsString(node: DerNode): string | null {
  if (node.tagClass !== TagClass.UNIVERSAL) return null;
  switch (node.tag) {
    case Tag.UTF8_STRING:
      return new TextDecoder('utf-8').decode(node.value);
    case Tag.PRINTABLE_STRING:
    case Tag.IA5_STRING:
    case Tag.GENERAL_STRING:
      return ascii(node.value);
    case Tag.T61_STRING:
      return latin1(node.value);
    case Tag.BMP_STRING:
      return utf16be(node.value);
    case Tag.UNIVERSAL_STRING:
      return utf32be(node.value);
    default:
      return null;
  }
}

/** Parses an encoded ASN.1 value and returns BouncyCastle's string for it, if it is a string. */
export function bcStringFromEncoded(encoded: Uint8Array): string | null {
  const node = parseDer(encoded, false);
  return isBcAsn1String(node) ? bcGetString(node) : null;
}

export function isUniversalString(node: DerNode): boolean {
  return isUniversal(node, Tag.UNIVERSAL_STRING);
}
