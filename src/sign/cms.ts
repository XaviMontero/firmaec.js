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
import { der, parseDer } from '../asn1/der.js';
import { Certificate } from '../x509/certificate.js';

/** Port of `sign.DigestAlgorithm` (subset used for signing). */
export type DigestAlgorithm = 'SHA1' | 'SHA256' | 'SHA384' | 'SHA512';

export const DIGEST_OIDS: Record<DigestAlgorithm, string> = {
  SHA1: '1.3.14.3.2.26',
  SHA256: '2.16.840.1.101.3.4.2.1',
  SHA384: '2.16.840.1.101.3.4.2.2',
  SHA512: '2.16.840.1.101.3.4.2.3',
};

const NODE_DIGEST: Record<DigestAlgorithm, string> = {
  SHA1: 'sha1',
  SHA256: 'sha256',
  SHA384: 'sha384',
  SHA512: 'sha512',
};

const RSA_SIG_OIDS: Record<DigestAlgorithm, string> = {
  SHA1: '1.2.840.113549.1.1.5',
  SHA256: '1.2.840.113549.1.1.11',
  SHA384: '1.2.840.113549.1.1.12',
  SHA512: '1.2.840.113549.1.1.13',
};

const ECDSA_SIG_OIDS: Record<DigestAlgorithm, string> = {
  SHA1: '1.2.840.10045.4.1',
  SHA256: '1.2.840.10045.4.3.2',
  SHA384: '1.2.840.10045.4.3.3',
  SHA512: '1.2.840.10045.4.3.4',
};

export const OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signatureTimeStampToken: '1.2.840.113549.1.9.16.2.14',
} as const;

export function nodeDigestName(alg: DigestAlgorithm): string {
  return NODE_DIGEST[alg];
}

export function digest(alg: DigestAlgorithm, ...chunks: Uint8Array[]): Buffer {
  const h = crypto.createHash(NODE_DIGEST[alg]);
  for (const c of chunks) h.update(c);
  return h.digest();
}

/** Port of `PrivateKeySigner.sign`: `<digest>with<RSA|ECDSA>` over the message. */
export function signMessage(alg: DigestAlgorithm, privateKey: crypto.KeyObject, message: Uint8Array): Buffer {
  if (privateKey.asymmetricKeyType === 'ec') {
    // Java SHA256withECDSA produces a DER encoded (r, s)
    return crypto.sign(NODE_DIGEST[alg], message, { key: privateKey, dsaEncoding: 'der' });
  }
  return crypto.sign(NODE_DIGEST[alg], message, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
}

export interface CmsOptions {
  digestAlgorithm: DigestAlgorithm;
  /** Signer certificate first. All of them are embedded (as iText does). */
  chain: Certificate[];
  privateKey: crypto.KeyObject;
  /** Hash of the signed content (the PDF byte ranges). */
  contentDigest: Buffer;
  /** Optional TSA: receives the signature value, returns a DER TimeStampToken. */
  timestamp?: (signatureValue: Buffer, digestAlgorithm: DigestAlgorithm) => Promise<Buffer>;
}

function algorithmIdentifier(oid: string, withNull = true): Buffer {
  return withNull ? der.sequence(der.oid(oid), der.null()) : der.sequence(der.oid(oid));
}

/**
 * Builds the authenticated attributes exactly like iText `PdfPKCS7.getAuthenticatedAttributeBytes`
 * for `CryptoStandard.CMS` without OCSP/CRL: contentType + messageDigest.
 */
export function authenticatedAttributes(contentDigest: Buffer): Buffer {
  return der.set(
    der.sequence(der.oid(OID.contentType), der.set(der.oid(OID.data))),
    der.sequence(der.oid(OID.messageDigest), der.set(der.octetString(contentDigest))),
  );
}

/**
 * Port of iText `PdfPKCS7.getEncodedPKCS7` (detached CMS SignedData, adbe.pkcs7.detached),
 * as used by `PadesBasicSigner` / `PadesEnhancedSigner`.
 */
export async function buildCmsSignedData(opts: CmsOptions): Promise<Buffer> {
  const { digestAlgorithm, chain, privateKey } = opts;
  const signer = chain[0];
  const attrs = authenticatedAttributes(opts.contentDigest);
  const signatureValue = signMessage(digestAlgorithm, privateKey, attrs);
  const isEc = privateKey.asymmetricKeyType === 'ec';
  const sigAlg = isEc
    ? algorithmIdentifier(ECDSA_SIG_OIDS[digestAlgorithm], false)
    : algorithmIdentifier(RSA_SIG_OIDS[digestAlgorithm]);
  const digestAlg = algorithmIdentifier(DIGEST_OIDS[digestAlgorithm]);

  let unsigned: Buffer[] = [];
  if (opts.timestamp) {
    const token = await opts.timestamp(signatureValue, digestAlgorithm);
    unsigned = [der.implicitConstructed(1, der.sequence(der.oid(OID.signatureTimeStampToken), der.set(token)))];
  }

  // [0] IMPLICIT: replace the SET tag of the attributes by the context tag
  const signedAttrs = der.implicitConstructed(0, parseDer(attrs).value);
  const signerInfo = der.sequence(
    der.integer(1),
    der.sequence(signer.issuer.der, der.integerRaw(signer.serialNumberBytes)),
    digestAlg,
    signedAttrs,
    sigAlg,
    der.octetString(signatureValue),
    ...unsigned,
  );
  const signedData = der.sequence(
    der.integer(1),
    der.set(digestAlg),
    der.sequence(der.oid(OID.data)),
    // iText wraps the certificates in a DERSet: sorted by encoding
    der.implicitConstructed(0, parseDer(der.set(...chain.map((c) => c.der))).value),
    der.set(signerInfo),
  );
  return der.sequence(der.oid(OID.signedData), der.explicit(0, signedData));
}
