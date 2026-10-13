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
import { Tag, decodeInteger, der, isUniversal, parseDer } from '../asn1/der.js';
import { TsaException } from '../errors.js';
import { DIGEST_OIDS, DigestAlgorithm, digest } from './cms.js';

export interface TsaOptions {
  url: string;
  username?: string;
  password?: string;
  /** Digest used for the message imprint (iText default: SHA-256). */
  digestAlgorithm?: DigestAlgorithm;
  timeoutMs?: number;
  /** Custom fetch (tests / proxies). */
  fetch?: typeof fetch;
}

/** Error carrying the HTTP status, like the "Server returned HTTP response code: N" of Java. */
export class TsaHttpError extends TsaException {
  constructor(
    readonly status: number,
    url: string,
  ) {
    super(`Server returned HTTP response code: ${status} for URL: ${url}`);
  }
}

/**
 * RFC 3161 client, port of iText `TSAClientBouncyCastle`.
 * Returns the DER encoded TimeStampToken (a CMS ContentInfo).
 */
export async function requestTimeStampToken(imprintSource: Uint8Array, opts: TsaOptions): Promise<Buffer> {
  const alg = opts.digestAlgorithm ?? 'SHA256';
  const imprint = digest(alg, imprintSource);
  const nonce = BigInt('0x' + crypto.randomBytes(8).toString('hex')) & ((1n << 63n) - 1n);
  const request = der.sequence(
    der.integer(1),
    der.sequence(der.sequence(der.oid(DIGEST_OIDS[alg]), der.null()), der.octetString(imprint)),
    der.integer(nonce),
    der.bool(true),
  );
  const headers: Record<string, string> = {
    'Content-Type': 'application/timestamp-query',
    'Content-Transfer-Encoding': 'binary',
  };
  if (opts.username !== undefined && opts.username !== '') {
    headers.Authorization =
      'Basic ' + Buffer.from(`${opts.username}:${opts.password ?? ''}`, 'utf8').toString('base64');
  }
  const doFetch = opts.fetch ?? fetch;
  const res = await doFetch(opts.url, {
    method: 'POST',
    headers,
    body: new Uint8Array(request),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
  });
  if (!res.ok) throw new TsaHttpError(res.status, opts.url);
  let body = Buffer.from(await res.arrayBuffer());
  if ((res.headers.get('content-encoding') ?? '').toLowerCase() === 'base64') {
    body = Buffer.from(body.toString('latin1'), 'base64');
  }
  return parseTimeStampResponse(body, imprint, nonce);
}

/** Validates a TimeStampResp (status, nonce, imprint) and returns its token. */
export function parseTimeStampResponse(body: Buffer, imprint: Buffer, nonce: bigint): Buffer {
  const resp = parseDer(body, false);
  const statusInfo = resp.children[0];
  const status = Number(decodeInteger(statusInfo.children[0].value));
  if (status !== 0 && status !== 1) {
    const text = statusInfo.children
      .slice(1)
      .filter((c) => isUniversal(c, Tag.SEQUENCE))
      .flatMap((c) => c.children.map((t) => t.value.toString('utf8')))
      .join(' ');
    throw new TsaException(`Invalid TSA '${status}' response, code ${status}${text ? ': ' + text : ''}`);
  }
  const token = resp.children[1];
  if (!token) throw new TsaException('TSA failed to return time stamp token');
  // TSTInfo: ContentInfo -> SignedData -> encapContentInfo -> [0] OCTET STRING
  const signedData = token.children[1].children[0];
  const encap = signedData.children.find((c, i) => i > 0 && isUniversal(c, Tag.SEQUENCE) && c.children.length >= 1);
  const octets = encap?.children[1]?.children[0];
  if (!octets) throw new TsaException('Respuesta TSA sin TSTInfo');
  const tstInfo = parseDer(octets.constructed ? Buffer.concat(octets.children.map((c) => c.value)) : octets.value);
  const messageImprint = tstInfo.children[2];
  const gotImprint = messageImprint.children[1].value;
  if (!gotImprint.equals(imprint)) throw new TsaException('La huella del sello de tiempo no coincide con la solicitada');
  const gotNonce = tstInfo.children.find((c, i) => i > 4 && isUniversal(c, Tag.INTEGER));
  if (gotNonce && decodeInteger(gotNonce.value) !== nonce) throw new TsaException('Nonce del sello de tiempo no coincide');
  return Buffer.from(token.raw);
}
