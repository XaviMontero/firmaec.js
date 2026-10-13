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
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { ExclusiveCanonicalization } from 'xml-crypto';
import { der } from '../asn1/der.js';
import { InvalidFormatException, RubricaException } from '../errors.js';
import { KeyStore } from '../keystore/keystore.js';
import { Certificate } from '../x509/certificate.js';

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const XADES = 'http://uri.etsi.org/01903/v1.3.2#';
const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';

/** Id of the node referenced by the SRI signature (`comprobanteReference.setUri("#comprobante")`). */
export const COMPROBANTE_ID = 'comprobante';

type XNode = any; // xmldom nodes

export interface XadesSignOptions {
  /** xades:SigningTime (default: now). */
  signingTime?: Date;
}

/**
 * Port of `sign.xades.XAdESSigner`: XAdES-BES (BASELINE-B) enveloped signature
 * over the node with id "comprobante", SHA-256, exclusive canonicalization,
 * as produced by EU DSS for the SRI (Ecuador electronic invoicing).
 */
export class XAdESSigner {
  /** Java signature: `sign(byte[] data, KeyStore keyStore, char[] claveFirma)` (first key entry). */
  async sign(data: Uint8Array, keyStore: KeyStore, _claveFirma?: string, options: XadesSignOptions = {}): Promise<Buffer> {
    const entry = keyStore.entries[0];
    if (!entry) throw new RubricaException('No se encontraron claves en el keystore');
    return this.signWithKey(data, entry.privateKey, entry.certificate, options);
  }

  async signWithKey(
    data: Uint8Array,
    privateKey: crypto.KeyObject,
    certificate: Certificate,
    options: XadesSignOptions = {},
  ): Promise<Buffer> {
    const xml = Buffer.from(data).toString('utf8');
    const errors: string[] = [];
    const doc: XNode = new DOMParser({
      onError: (level: string, msg: string) => {
        if (level !== 'warning') errors.push(msg);
      },
    }).parseFromString(xml, 'text/xml');
    if (errors.length || !doc?.documentElement) {
      throw new InvalidFormatException('Documento XML inválido: ' + errors.join('; '));
    }
    const root = doc.documentElement;
    const target = findById(root, COMPROBANTE_ID);
    if (!target) {
      throw new InvalidFormatException(`El documento no contiene un nodo con id="${COMPROBANTE_ID}"`);
    }

    const signingTime = new Date(Math.floor((options.signingTime ?? new Date()).getTime() / 1000) * 1000);
    const id = deterministicId(signingTime, certificate);
    const isEc = privateKey.asymmetricKeyType === 'ec';

    // Reference #comprobante: enveloped-signature + exc-c14n (computed before the signature exists)
    const referenceDigest = sha(256, c14n(target));

    const certDigest = crypto.createHash('sha512').update(certificate.der).digest('base64');
    const issuerSerial = der
      .sequence(der.sequence(der.explicit(4, certificate.issuer.der)), der.integerRaw(certificate.serialNumberBytes))
      .toString('base64');

    const signedProperties =
      `<xades:SignedProperties Id="xades-${id}">` +
      `<xades:SignedSignatureProperties>` +
      `<xades:SigningTime>${signingTime.toISOString().replace(/\.\d{3}Z$/, 'Z')}</xades:SigningTime>` +
      `<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>` +
      `<ds:DigestMethod Algorithm="${SHA512}"/><ds:DigestValue>${certDigest}</ds:DigestValue>` +
      `</xades:CertDigest><xades:IssuerSerialV2>${issuerSerial}</xades:IssuerSerialV2></xades:Cert></xades:SigningCertificateV2>` +
      `</xades:SignedSignatureProperties>` +
      `<xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference="#r-${id}-1">` +
      `<xades:MimeType>application/octet-stream</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties>` +
      `</xades:SignedProperties>`;

    const signatureXml =
      `<ds:Signature xmlns:ds="${DS}" Id="${id}">` +
      `<ds:SignedInfo>` +
      `<ds:CanonicalizationMethod Algorithm="${EXC_C14N}"/>` +
      `<ds:SignatureMethod Algorithm="${isEc ? ECDSA_SHA256 : RSA_SHA256}"/>` +
      `<ds:Reference Id="r-${id}-1" URI="#${COMPROBANTE_ID}"><ds:Transforms>` +
      `<ds:Transform Algorithm="${ENVELOPED}"/><ds:Transform Algorithm="${EXC_C14N}"/></ds:Transforms>` +
      `<ds:DigestMethod Algorithm="${SHA256}"/><ds:DigestValue>${referenceDigest}</ds:DigestValue></ds:Reference>` +
      `<ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades-${id}"><ds:Transforms>` +
      `<ds:Transform Algorithm="${EXC_C14N}"/></ds:Transforms>` +
      `<ds:DigestMethod Algorithm="${SHA256}"/><ds:DigestValue></ds:DigestValue></ds:Reference>` +
      `</ds:SignedInfo>` +
      `<ds:SignatureValue Id="value-${id}"></ds:SignatureValue>` +
      `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certificate.der.toString('base64')}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
      `<ds:Object><xades:QualifyingProperties xmlns:xades="${XADES}" Target="#${id}">${signedProperties}</xades:QualifyingProperties></ds:Object>` +
      `</ds:Signature>`;

    const sigDoc = new DOMParser().parseFromString(signatureXml, 'text/xml');
    const signature = doc.importNode(sigDoc.documentElement, true);
    root.appendChild(signature);

    const byLocal = (local: string, ns: string) => Array.from(signature.getElementsByTagNameNS(ns, local) as ArrayLike<XNode>);
    const signedPropsNode = byLocal('SignedProperties', XADES)[0];
    const digestValues = byLocal('DigestValue', DS).filter((n) => n.parentNode.localName === 'Reference');
    digestValues[1].appendChild(doc.createTextNode(sha(256, c14n(signedPropsNode))));

    const signedInfo = byLocal('SignedInfo', DS)[0];
    const signedInfoC14n = c14n(signedInfo);
    const value = isEc
      ? crypto.sign('sha256', Buffer.from(signedInfoC14n, 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' })
      : crypto.sign('sha256', Buffer.from(signedInfoC14n, 'utf8'), privateKey);
    byLocal('SignatureValue', DS)[0].appendChild(doc.createTextNode(value.toString('base64')));

    return Buffer.from(serializeLikeDss(doc), 'utf8');
  }
}

function sha(bits: 256 | 512, s: string): string {
  return crypto.createHash('sha' + bits).update(Buffer.from(s, 'utf8')).digest('base64');
}

function c14n(node: XNode): string {
  return new ExclusiveCanonicalization().process(node, { inclusiveNamespacesPrefixList: [] }) as string;
}

/** DSS resolves "#x" against attributes named Id, id or ID. */
function findById(node: XNode, id: string): XNode | null {
  if (node.nodeType === 1) {
    for (const a of ['Id', 'id', 'ID']) if (node.getAttribute(a) === id) return node;
    for (let c = node.firstChild; c; c = c.nextSibling) {
      const r = findById(c, id);
      if (r) return r;
    }
  }
  return null;
}

/** DSS `DSSUtils.getDeterministicId`-like: "id-" + MD5(signing time + certificate). */
function deterministicId(signingTime: Date, certificate: Certificate): string {
  return (
    'id-' +
    crypto
      .createHash('md5')
      .update(String(signingTime.getTime()))
      .update(certificate.der)
      .digest('hex')
  );
}

/** Serializes like DSS (JAXP transformer): XML declaration with standalone="no", root right after it. */
function serializeLikeDss(doc: XNode): string {
  const ser = new XMLSerializer();
  let out = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>';
  for (let n = doc.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 7 && n.target === 'xml') continue; // the original declaration
    if (n.nodeType === 3) continue; // whitespace between top level nodes is not kept by the transformer
    out += ser.serializeToString(n);
  }
  return out;
}
