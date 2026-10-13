/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import { TagClass, decodeOid, isUniversal, parseDer, Tag } from '../asn1/der.js';
import { Certificate } from '../x509/certificate.js';
import { bcGetString, bcToString, isBcAsn1String } from '../x509/strings.js';

/**
 * Port of `CertUtils.getExtensionValue`: the extension content is parsed and,
 * when it is an ASN.1 string, its value is returned.
 */
export function getExtensionValue(cert: Certificate, oid: string): string | null {
  const ext = cert.getExtension(oid);
  if (!ext) return null;
  try {
    const node = parseDer(ext.value, false);
    return isBcAsn1String(node) ? bcGetString(node) : null;
  } catch {
    return null;
  }
}

/** Port of `CertUtils.getSubjectAlternativeName` (otherName lookup by OID). */
export function getSubjectAlternativeName(cert: Certificate, oid: string): string | null {
  const altNames = cert.getSubjectAlternativeNames();
  if (!altNames) return null;
  for (const [type, value] of altNames) {
    if (type !== 0 || !Buffer.isBuffer(value)) continue;
    const object = parseDer(value, false);
    if (isUniversal(object, Tag.SEQUENCE)) {
      if (decodeOid(object.children[0].value) === oid) {
        return bcToString(object.children[1]).replace('[0]', '').replace('[CONTEXT 0]', '');
      }
    }
    if (object.tagClass !== TagClass.UNIVERSAL && object.constructed && object.children.length === 1) {
      const seq = object.children[0];
      if (isUniversal(seq, Tag.SEQUENCE) && decodeOid(seq.children[0].value) === oid) {
        const detail = seq.children[1];
        return bcToString(detail.children.length === 1 ? detail.children[0] : detail);
      }
    }
  }
  return null;
}

/** Port of `CertUtils.getSubjectFieldByOID` over the certificate subject. */
export function getSubjectFieldByOid(cert: Certificate, oid: string): string | null {
  return cert.subject.getBcField(oid);
}

/** Port of `BouncyCastleUtils.certificateHasPolicy`. */
export function certificateHasPolicy(cert: Certificate, policyOid: string): boolean {
  return cert.hasPolicy(policyOid);
}

/** Port of `Utils.getRDNvalueFromLdapName`. */
export function getRDNvalueFromLdapName(rdn: string, principal: string): string | null {
  let offset1 = 0;
  const lower = principal.toLowerCase();
  const rdnLower = rdn.toLowerCase();
  while ((offset1 = lower.indexOf(rdnLower, offset1)) !== -1) {
    if (offset1 > 0 && principal[offset1 - 1] !== ',' && principal[offset1 - 1] !== ' ') {
      offset1++;
      continue;
    }
    offset1 += rdn.length;
    while (offset1 < principal.length && principal[offset1] === ' ') offset1++;
    if (offset1 >= principal.length) return null;
    if (principal[offset1] !== '=') continue;
    offset1++;
    while (offset1 < principal.length && principal[offset1] === ' ') offset1++;
    if (offset1 >= principal.length) return '';
    let offset2: number;
    switch (principal[offset1]) {
      case ',':
        return '';
      case '"':
        offset1++;
        if (offset1 >= principal.length) return '';
        offset2 = principal.indexOf('"', offset1);
        if (offset2 === offset1) return '';
        if (offset2 !== -1) return principal.substring(offset1, offset2);
        return principal.substring(offset1);
      default:
        offset2 = principal.indexOf(',', offset1);
        if (offset2 !== -1) return javaTrim(principal.substring(offset1, offset2));
        return javaTrim(principal.substring(offset1));
    }
  }
  return null;
}

/** Java `String.trim()` (strips chars <= U+0020). */
export function javaTrim(s: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && s.charCodeAt(a) <= 0x20) a++;
  while (b > a && s.charCodeAt(b - 1) <= 0x20) b--;
  return s.substring(a, b);
}

/** Port of `Util.getCN(String principal)`. */
export function getCNFromPrincipal(principal: string | null): string | null {
  if (principal === null) return null;
  let rdn = getRDNvalueFromLdapName('cn', principal);
  if (rdn === null) rdn = getRDNvalueFromLdapName('ou', principal);
  if (rdn !== null) return rdn;
  const i = principal.indexOf('=');
  if (i !== -1) return getRDNvalueFromLdapName(principal.substring(0, i), principal);
  return principal;
}

/** Port of `Util.getCN(X509Certificate)` / `CertificateUtils.getCN`. */
export function getCN(cert: Certificate | null): string | null {
  if (!cert) return null;
  return getCNFromPrincipal(cert.subjectPrincipal);
}

/** Port of `CertificateUtils.getEmail`. */
export function getEmail(cert: Certificate | null): string | null {
  if (!cert) return null;
  try {
    const altNames = cert.getSubjectAlternativeNames();
    if (altNames) {
      for (const [type, value] of altNames) {
        if (type === 1) return value as string;
      }
    }
  } catch {
    // ignorar y continuar con Subject DN
  }
  const principal = cert.subjectPrincipal;
  let email = getRDNvalueFromLdapName('emailaddress', principal);
  if (email === null) email = getRDNvalueFromLdapName('e', principal);
  return email;
}

/** Port of `Utils.verifySignature(certificate, rootCertificate)`. */
export function verifySignature(cert: Certificate, root: Certificate | null): boolean {
  if (!root) return false;
  return cert.isSignedBy(root);
}
