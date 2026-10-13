/**
 * Test PKI: builds X.509 certificates with arbitrary subject attributes and
 * extensions (to mimic the Ecuadorian CAs) and packs them into .p12 files.
 */
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import forge from 'node-forge';
import { Tag, TagClass, der, tlv } from '../../src/asn1/der.js';

export type StringType = 'utf8' | 'printable' | 'ia5' | 'bmp' | 't61';

/** One attribute: [oid or short name, value, string type]. */
export type Atv = [string, string, StringType?];
/** DN in DER order (country first). An inner array of Atv makes a multi-valued RDN. */
export type NameSpec = Array<Atv | Atv[]>;

const SHORT: Record<string, string> = {
  C: '2.5.4.6',
  O: '2.5.4.10',
  OU: '2.5.4.11',
  CN: '2.5.4.3',
  L: '2.5.4.7',
  ST: '2.5.4.8',
  SN: '2.5.4.4',
  SURNAME: '2.5.4.4',
  GN: '2.5.4.42',
  GIVENNAME: '2.5.4.42',
  SERIALNUMBER: '2.5.4.5',
  T: '2.5.4.12',
  TITLE: '2.5.4.12',
  ORGID: '2.5.4.97',
  E: '1.2.840.113549.1.9.1',
  EMAIL: '1.2.840.113549.1.9.1',
  STREET: '2.5.4.9',
  UID: '0.9.2342.19200300.100.1.1',
};

export function encodeString(value: string, type: StringType = 'utf8'): Buffer {
  switch (type) {
    case 'utf8':
      return der.utf8(value);
    case 'printable':
      return der.printable(value);
    case 'ia5':
      return der.ia5(value);
    case 't61':
      return tlv(TagClass.UNIVERSAL, false, Tag.T61_STRING, Buffer.from(value, 'latin1'));
    case 'bmp': {
      const b = Buffer.from(value, 'utf16le');
      b.swap16();
      return tlv(TagClass.UNIVERSAL, false, Tag.BMP_STRING, b);
    }
  }
}

function encodeAtv([type, value, st]: Atv): Buffer {
  const oid = SHORT[type.toUpperCase()] ?? type;
  const defaultType: StringType = oid === '2.5.4.6' || oid === '2.5.4.5' ? 'printable' : oid === SHORT.E ? 'ia5' : 'utf8';
  return der.sequence(der.oid(oid), encodeString(value, st ?? defaultType));
}

export function encodeName(name: NameSpec): Buffer {
  return der.sequence(
    ...name.map((rdn) => (Array.isArray(rdn[0]) ? der.set(...(rdn as Atv[]).map(encodeAtv)) : der.set(encodeAtv(rdn as Atv)))),
  );
}

export interface ExtSpec {
  oid: string;
  critical?: boolean;
  /** DER of the extension value (content of extnValue). */
  value: Buffer;
}

/** Extension builders. */
export const ext = {
  raw: (oid: string, value: Buffer, critical = false): ExtSpec => ({ oid, value, critical }),
  /** Extension whose value is an ASN.1 string (the Ecuadorian CA style). */
  string: (oid: string, value: string, type: StringType = 'utf8'): ExtSpec => ({ oid, value: encodeString(value, type) }),
  policies: (...oids: string[]): ExtSpec => ({
    oid: '2.5.29.32',
    value: der.sequence(...oids.map((o) => der.sequence(der.oid(o)))),
  }),
  keyUsage: (...bits: number[]): ExtSpec => {
    let v = 0;
    for (const b of bits) v |= 0x8000 >> b;
    const bytes = Buffer.from([v >> 8, v & 0xff]);
    const used = bytes[1] ? 2 : 1;
    const last = bytes[used - 1];
    let unused = 0;
    while (unused < 7 && !(last & (1 << unused))) unused++;
    return { oid: '2.5.29.15', critical: true, value: der.bitString(bytes.subarray(0, used), unused) };
  },
  basicConstraints: (ca: boolean): ExtSpec => ({
    oid: '2.5.29.19',
    critical: true,
    value: ca ? der.sequence(der.bool(true)) : der.sequence(),
  }),
  /** subjectAltName with rfc822Name and/or otherNames ([0] EXPLICIT value DER). */
  san: (opts: { email?: string; dns?: string; otherNames?: Array<{ oid: string; value: Buffer }> }): ExtSpec => {
    const names: Buffer[] = [];
    if (opts.email) names.push(der.implicitPrimitive(1, Buffer.from(opts.email, 'latin1')));
    if (opts.dns) names.push(der.implicitPrimitive(2, Buffer.from(opts.dns, 'latin1')));
    for (const on of opts.otherNames ?? []) {
      names.push(der.implicitConstructed(0, Buffer.concat([der.oid(on.oid), der.explicit(0, on.value)])));
    }
    return { oid: '2.5.29.17', value: der.sequence(...names) };
  },
};

export interface KeyPair {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
}

const keyCache = new Map<string, KeyPair>();

/** Key pairs are cached per label to keep tests fast. */
export function keyPair(label = 'default', type: 'rsa' | 'ec' = 'rsa'): KeyPair {
  const k = `${type}:${label}`;
  let kp = keyCache.get(k);
  if (!kp) {
    kp =
      type === 'rsa'
        ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
        : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    keyCache.set(k, kp);
  }
  return kp;
}

export interface CertOptions {
  subject: NameSpec;
  issuer?: { name: NameSpec; key: crypto.KeyObject; cert?: Buffer };
  publicKey: crypto.KeyObject;
  /** Signing key when self signed. */
  privateKey?: crypto.KeyObject;
  serial?: bigint;
  notBefore?: Date;
  notAfter?: Date;
  extensions?: ExtSpec[];
}

let serialCounter = 0x1000n;

export function buildCertificate(opts: CertOptions): Buffer {
  const issuerName = encodeName(opts.issuer?.name ?? opts.subject);
  const signKey = opts.issuer?.key ?? opts.privateKey;
  if (!signKey) throw new Error('sin clave de firma');
  const isEc = signKey.asymmetricKeyType === 'ec';
  const sigAlg = isEc ? der.sequence(der.oid('1.2.840.10045.4.3.2')) : der.sequence(der.oid('1.2.840.113549.1.1.11'), der.null());
  const spki = opts.publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const exts = opts.extensions ?? [];
  const tbs = der.sequence(
    der.explicit(0, der.integer(2)),
    der.integer(opts.serial ?? serialCounter++),
    sigAlg,
    issuerName,
    der.sequence(
      der.utcTime(opts.notBefore ?? new Date(Date.now() - 86400_000)),
      der.utcTime(opts.notAfter ?? new Date(Date.now() + 2 * 365 * 86400_000)),
    ),
    encodeName(opts.subject),
    spki,
    ...(exts.length
      ? [
          der.explicit(
            3,
            der.sequence(
              ...exts.map((e) =>
                der.sequence(der.oid(e.oid), ...(e.critical ? [der.bool(true)] : []), der.octetString(e.value)),
              ),
            ),
          ),
        ]
      : []),
  );
  const signature = crypto.sign('sha256', tbs, signKey);
  return der.sequence(tbs, sigAlg, der.bitString(signature));
}

export function toPem(derCert: Buffer): string {
  return `-----BEGIN CERTIFICATE-----\n${derCert.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END CERTIFICATE-----\n`;
}

export interface TestCa {
  name: NameSpec;
  key: KeyPair;
  cert: Buffer;
}

/** Self signed CA whose subject is `name` (e.g. O = the Ecuadorian CA organization). */
export function createCa(name: NameSpec, label = 'ca', type: 'rsa' | 'ec' = 'rsa'): TestCa {
  const key = keyPair(label, type);
  const cert = buildCertificate({
    subject: name,
    publicKey: key.publicKey,
    privateKey: key.privateKey,
    extensions: [ext.basicConstraints(true), ext.keyUsage(5, 6)],
    notBefore: new Date(Date.UTC(2020, 0, 1)),
    notAfter: new Date(Date.UTC(2040, 0, 1)),
  });
  return { name, key, cert };
}

export interface TestSigner {
  cert: Buffer;
  key: KeyPair;
  chain: Buffer[];
}

export function issue(
  ca: TestCa,
  subject: NameSpec,
  extensions: ExtSpec[],
  opts: { label?: string; type?: 'rsa' | 'ec'; withKeyUsage?: boolean; notBefore?: Date; notAfter?: Date } = {},
): TestSigner {
  const key = keyPair(opts.label ?? 'leaf', opts.type ?? 'rsa');
  const cert = buildCertificate({
    subject,
    issuer: { name: ca.name, key: ca.key.privateKey },
    publicKey: key.publicKey,
    extensions: [...(opts.withKeyUsage === false ? [] : [ext.keyUsage(0, 1)]), ...extensions],
    notBefore: opts.notBefore,
    notAfter: opts.notAfter,
  });
  return { cert, key, chain: [cert, ca.cert] };
}

/** Packs a signer into a PKCS#12 file. `legacy` uses 3DES/RC2-40 (like many Ecuadorian tokens). */
export function toP12(signer: TestSigner, password: string, opts: { legacy?: boolean; friendlyName?: string } = {}): Buffer {
  if (signer.key.privateKey.asymmetricKeyType === 'rsa') {
    const key = forge.pki.privateKeyFromPem(signer.key.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string);
    const certs = signer.chain.map((c) => forge.pki.certificateFromAsn1(forge.asn1.fromDer(c.toString('binary'))));
    const asn1 = forge.pkcs12.toPkcs12Asn1(key, certs, password, {
      algorithm: opts.legacy ? '3des' : 'aes256',
      friendlyName: opts.friendlyName ?? 'firmante',
      generateLocalKeyId: true,
    });
    return Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary');
  }
  // EC keys: forge cannot build them, use openssl
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'p12-'));
  try {
    fs.writeFileSync(path.join(dir, 'key.pem'), signer.key.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string);
    fs.writeFileSync(path.join(dir, 'cert.pem'), toPem(signer.chain[0]));
    fs.writeFileSync(path.join(dir, 'chain.pem'), signer.chain.slice(1).map(toPem).join(''));
    execFileSync('openssl', [
      'pkcs12', '-export', '-inkey', path.join(dir, 'key.pem'), '-in', path.join(dir, 'cert.pem'),
      '-certfile', path.join(dir, 'chain.pem'), '-name', opts.friendlyName ?? 'firmante',
      '-out', path.join(dir, 'out.p12'), '-passout', 'pass:' + password,
      ...(opts.legacy ? ['-legacy'] : []),
    ]);
    return fs.readFileSync(path.join(dir, 'out.p12'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
