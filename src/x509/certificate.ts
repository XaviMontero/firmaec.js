/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import crypto from 'node:crypto';
import {
  DerNode,
  Tag,
  decodeInteger,
  decodeOid,
  decodeTime,
  isContext,
  isUniversal,
  parseDer,
} from '../asn1/der.js';
import { bcToString, bcValueToString, jdkGetAsString } from './strings.js';

export interface AttributeTypeAndValue {
  oid: string;
  value: DerNode;
}

/** An X.500 distinguished name: RDNs in DER (encoding) order. */
export class X500Name {
  constructor(
    readonly rdns: AttributeTypeAndValue[][],
    readonly der: Buffer,
  ) {}

  static fromNode(node: DerNode): X500Name {
    const rdns = node.children.map((set) =>
      set.children.map((atv) => ({ oid: decodeOid(atv.children[0].value), value: atv.children[1] })),
    );
    return new X500Name(rdns, Buffer.from(node.raw));
  }

  /** JDK `X500Principal.toString()` (sun.security.x509.X500Name default format). */
  toJavaString(): string {
    return [...this.rdns]
      .reverse()
      .map((rdn) => rdn.map(javaAvaToString).join(' + '))
      .join(', ');
  }

  /** BouncyCastle `X500Name.getRDNs(oid)[0].getFirst()` -> `IETFUtils.valueToString`. */
  getBcField(oid: string): string | null {
    const rdn = this.rdns.find((r) => r.some((atv) => atv.oid === oid));
    if (!rdn) return null;
    return bcValueToString(rdn[0].value);
  }

  /** JDK `X500Principal.getName()` (RFC 2253). */
  toRfc2253(): string {
    return [...this.rdns]
      .reverse()
      .map((rdn) => rdn.map(javaAvaToRfc2253).join('+'))
      .join(',');
  }

  /** Display form. */
  toString(): string {
    return this.toJavaString();
  }

  equals(other: X500Name): boolean {
    return this.der.equals(other.der);
  }
}

/** Keywords of sun.security.x509.AVA for the DEFAULT format (last registration wins). */
const JDK_KEYWORDS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'T',
  '1.3.6.1.4.1.42.2.11.2.1': 'IP',
  '2.5.4.9': 'STREET',
  '0.9.2342.19200300.100.1.25': 'DC',
  '2.5.4.46': 'DNQ',
  '2.5.4.4': 'SURNAME',
  '2.5.4.42': 'GIVENNAME',
  '2.5.4.43': 'INITIALS',
  '2.5.4.44': 'GENERATION',
  '1.2.840.113549.1.9.1': 'EMAILADDRESS',
  '0.9.2342.19200300.100.1.1': 'UID',
  '2.5.4.5': 'SERIALNUMBER',
};

const RFC2253_KEYWORDS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.9': 'STREET',
  '0.9.2342.19200300.100.1.25': 'DC',
  '0.9.2342.19200300.100.1.1': 'UID',
};

const DER_STRING_TAGS = new Set<number>([
  Tag.PRINTABLE_STRING,
  Tag.T61_STRING,
  Tag.IA5_STRING,
  Tag.GENERAL_STRING,
  Tag.BMP_STRING,
  Tag.UTF8_STRING,
]);

/** sun.security.x509.AVA#toRFC2253String */
function javaAvaToRfc2253(atv: AttributeTypeAndValue): string {
  const keyword = RFC2253_KEYWORDS[atv.oid] ?? atv.oid;
  const isString = atv.value.tagClass === 0 && DER_STRING_TAGS.has(atv.value.tag);
  if (/^[0-9]/.test(keyword) || !isString) {
    return keyword + '=#' + atv.value.raw.toString('hex');
  }
  const valStr = new TextDecoder('utf-8').decode(atv.value.value);
  const escapees = ',=+<>#;"\\';
  let sb = '';
  for (const c of valStr) {
    if (isPrintableStringChar(c) || escapees.includes(c)) {
      if (escapees.includes(c)) sb += '\\';
      sb += c;
    } else if (c === '\u0000') {
      sb += '\\00';
    } else {
      sb += c;
    }
  }
  let lead = 0;
  while (lead < sb.length && (sb[lead] === ' ' || sb[lead] === '\r')) lead++;
  let trail = sb.length - 1;
  while (trail >= 0 && (sb[trail] === ' ' || sb[trail] === '\r')) trail--;
  let out = '';
  for (let i = 0; i < sb.length; i++) {
    if (i < lead || i > trail) out += '\\';
    out += sb[i];
  }
  return keyword + '=' + out;
}

function isPrintableStringChar(c: string): boolean {
  return /^[A-Za-z0-9 '()+,\-./:=?]$/.test(c);
}

/** sun.security.x509.AVA#toKeywordValueString */
function javaAvaToString(atv: AttributeTypeAndValue): string {
  const keyword = JDK_KEYWORDS[atv.oid] ?? 'OID.' + atv.oid;
  const valStr = jdkGetAsString(atv.value);
  if (valStr === null) {
    return keyword + '=#' + atv.value.raw.toString('hex');
  }
  const escapees = ',+=\n<>#;\\"';
  let quoteNeeded = false;
  let previousWhite = false;
  let sb = '';
  // Java iterates UTF-16 code units
  const length = valStr.length;
  const alreadyQuoted = length > 1 && valStr[0] === '"' && valStr[length - 1] === '"';
  for (let i = 0; i < length; i++) {
    const c = valStr[i];
    if (alreadyQuoted && (i === 0 || i === length - 1)) {
      sb += c;
      continue;
    }
    if (isPrintableStringChar(c) || escapees.includes(c)) {
      if (!quoteNeeded && ((i === 0 && (c === ' ' || c === '\n')) || escapees.includes(c))) {
        quoteNeeded = true;
      }
      if (!(c === ' ' || c === '\n')) {
        if (c === '"' || c === '\\') sb += '\\';
        previousWhite = false;
      } else {
        if (!quoteNeeded && previousWhite) quoteNeeded = true;
        previousWhite = true;
      }
      sb += c;
    } else {
      previousWhite = false;
      sb += c;
    }
  }
  if (sb.length > 0) {
    const trail = sb[sb.length - 1];
    if (trail === ' ' || trail === '\n') quoteNeeded = true;
  }
  return keyword + '=' + (!alreadyQuoted && quoteNeeded ? '"' + sb + '"' : sb);
}

export interface Extension {
  oid: string;
  critical: boolean;
  /** Content of extnValue (the DER of the extension itself). */
  value: Buffer;
}

/** Java-like `[type, value]` entries of `X509Certificate.getSubjectAlternativeNames()`. */
export type AltName = [number, string | Buffer];

/**
 * X.509 certificate with the accessors the original Java code relies on.
 * Parsing is done by hand so certificates with any key type are accepted.
 */
export class Certificate {
  readonly der: Buffer;
  readonly version: number;
  readonly serialNumber: bigint;
  readonly serialNumberBytes: Buffer;
  readonly issuer: X500Name;
  readonly subject: X500Name;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly extensions: Map<string, Extension>;
  readonly tbs: Buffer;
  readonly signatureAlgorithmOid: string;
  readonly subjectPublicKeyInfo: Buffer;
  private nodeCert?: crypto.X509Certificate;

  constructor(input: Uint8Array | string) {
    this.der = Certificate.toDer(input);
    const root = parseDer(this.der);
    const tbs = root.children[0];
    this.tbs = Buffer.from(tbs.raw);
    this.signatureAlgorithmOid = decodeOid(root.children[1].children[0].value);
    let i = 0;
    let version = 1;
    if (isContext(tbs.children[0], 0)) {
      version = Number(decodeInteger(tbs.children[0].children[0].value)) + 1;
      i++;
    }
    this.version = version;
    this.serialNumberBytes = Buffer.from(tbs.children[i].value);
    this.serialNumber = decodeInteger(tbs.children[i++].value);
    i++; // signature algorithm
    this.issuer = X500Name.fromNode(tbs.children[i++]);
    const validity = tbs.children[i++];
    this.notBefore = decodeTime(validity.children[0]);
    this.notAfter = decodeTime(validity.children[1]);
    this.subject = X500Name.fromNode(tbs.children[i++]);
    this.subjectPublicKeyInfo = Buffer.from(tbs.children[i++].raw);
    this.extensions = new Map();
    for (; i < tbs.children.length; i++) {
      const n = tbs.children[i];
      if (isContext(n, 3)) {
        for (const ext of n.children[0].children) {
          const oid = decodeOid(ext.children[0].value);
          const critical = ext.children.length === 3 && ext.children[1].value[0] !== 0;
          const value = Buffer.from(ext.children[ext.children.length - 1].value);
          this.extensions.set(oid, { oid, critical, value });
        }
      }
    }
  }

  static toDer(input: Uint8Array | string): Buffer {
    if (typeof input === 'string' || looksLikePem(input)) {
      const text = typeof input === 'string' ? input : Buffer.from(input).toString('latin1');
      const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(text);
      if (!m) throw new Error('Certificado PEM invalido');
      return Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
    }
    return Buffer.from(input);
  }

  get node(): crypto.X509Certificate {
    if (!this.nodeCert) this.nodeCert = new crypto.X509Certificate(this.der);
    return this.nodeCert;
  }

  get publicKey(): crypto.KeyObject {
    return crypto.createPublicKey({ key: this.subjectPublicKeyInfo, format: 'der', type: 'spki' });
  }

  /** "RSA" | "EC" | ... like `PublicKey.getAlgorithm()` */
  get keyAlgorithm(): string {
    const t = this.publicKey.asymmetricKeyType;
    return t === 'rsa' || t === 'rsa-pss' ? 'RSA' : t === 'ec' ? 'EC' : String(t).toUpperCase();
  }

  /** Java `getIssuerX500Principal().toString()` */
  get issuerPrincipal(): string {
    return this.issuer.toJavaString();
  }

  /** Java `getSubjectX500Principal().toString()` */
  get subjectPrincipal(): string {
    return this.subject.toJavaString();
  }

  /** Raw extension value (contents of extnValue) */
  getExtension(oid: string): Extension | undefined {
    return this.extensions.get(oid);
  }

  /** Java `X509Certificate.getKeyUsage()` */
  getKeyUsage(): boolean[] | null {
    const ext = this.extensions.get('2.5.29.15');
    if (!ext) return null;
    const bits = parseDer(ext.value);
    const unused = bits.value[0];
    const data = bits.value.subarray(1);
    const len = data.length * 8 - unused;
    const out: boolean[] = [];
    for (let i = 0; i < Math.max(len, 9); i++) {
      out.push(i < len ? (data[i >> 3] & (0x80 >> (i & 7))) !== 0 : false);
    }
    return out;
  }

  /** Java `getBasicConstraints()`: -1 if not a CA, else pathLen (Integer.MAX_VALUE if unbounded). */
  getBasicConstraints(): number {
    const ext = this.extensions.get('2.5.29.19');
    if (!ext) return -1;
    const seq = parseDer(ext.value);
    let isCa = false;
    let pathLen = 2147483647;
    for (const c of seq.children) {
      if (isUniversal(c, Tag.BOOLEAN)) isCa = c.value[0] !== 0;
      if (isUniversal(c, Tag.INTEGER)) pathLen = Number(decodeInteger(c.value));
    }
    return isCa ? pathLen : -1;
  }

  /** Policy identifiers of the CertificatePolicies extension. */
  getPolicyOids(): string[] {
    const ext = this.extensions.get('2.5.29.32');
    if (!ext) return [];
    try {
      return parseDer(ext.value).children.map((p) => decodeOid(p.children[0].value));
    } catch {
      return [];
    }
  }

  hasPolicy(oid: string): boolean {
    return this.getPolicyOids().includes(oid);
  }

  /**
   * Java `getSubjectAlternativeNames()`: [type, value] with string values for
   * rfc822Name(1), dNSName(2), URI(6), IP(7), registeredID(8), directoryName(4)
   * and the DER encoding for otherName(0), x400(3) and ediPartyName(5).
   */
  getSubjectAlternativeNames(): AltName[] | null {
    const ext = this.extensions.get('2.5.29.17');
    if (!ext) return null;
    const out: AltName[] = [];
    for (const gn of parseDer(ext.value).children) {
      switch (gn.tag) {
        case 0:
          // JDK re-encodes OtherName as SEQUENCE { type-id, [0] EXPLICIT value }
          out.push([0, Buffer.concat([Buffer.from([0x30]), encodeLen(gn.value.length), gn.value])]);
          break;
        case 1:
        case 2:
        case 6:
          out.push([gn.tag, gn.value.toString('latin1')]);
          break;
        case 4:
          out.push([4, X500Name.fromNode(gn.children[0]).toJavaString()]);
          break;
        case 7:
          out.push([7, formatIp(gn.value)]);
          break;
        case 8:
          out.push([8, decodeOid(gn.value)]);
          break;
        default:
          out.push([gn.tag, Buffer.from(gn.raw)]);
      }
    }
    return out;
  }

  /** Verifies that this certificate was signed by `issuer` (Java `verify(issuer.getPublicKey())`). */
  isSignedBy(issuer: Certificate): boolean {
    try {
      return this.node.verify(issuer.publicKey);
    } catch {
      return false;
    }
  }

  isSelfSigned(): boolean {
    return this.issuer.equals(this.subject) && this.isSignedBy(this);
  }

  /** Validity check like Java `checkValidity(date)`. */
  isValidAt(date: Date = new Date()): boolean {
    return date >= this.notBefore && date <= this.notAfter;
  }

  toPem(): string {
    const b64 = this.der.toString('base64').replace(/(.{64})/g, '$1\n');
    return `-----BEGIN CERTIFICATE-----\n${b64.replace(/\n$/, '')}\n-----END CERTIFICATE-----\n`;
  }

  equals(other: Certificate): boolean {
    return this.der.equals(other.der);
  }

  /** BouncyCastle toString of an otherName value, helper for CA parsers. */
  static bcToString(node: DerNode): string {
    return bcToString(node);
  }
}

function looksLikePem(input: Uint8Array): boolean {
  return Buffer.from(input.subarray(0, 64)).toString('latin1').includes('-----BEGIN');
}

function encodeLen(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  while (len > 0) {
    bytes.unshift(len & 0xff);
    len >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function formatIp(b: Buffer): string {
  if (b.length === 4) return [...b].join('.');
  const parts: string[] = [];
  for (let i = 0; i < b.length; i += 2) parts.push(b.readUInt16BE(i).toString(16));
  return parts.join(':');
}

export { jdkGetAsString };
