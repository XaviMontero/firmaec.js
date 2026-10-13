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
import forge from 'node-forge';
import { AliasesNotFoundException, RubricaException } from '../errors.js';
import { Certificate } from '../x509/certificate.js';
import { getCN } from '../certificate/cert-utils.js';

/** A private key entry of a PKCS#12 keystore. */
export interface KeyEntry {
  /** Alias (friendlyName, lower case like Java's PKCS12 KeyStore). */
  alias: string;
  privateKey: crypto.KeyObject;
  /** Signer certificate followed by its issuers, as Java `getCertificateChain`. */
  chain: Certificate[];
  certificate: Certificate;
}

/** Port of `keystore.Alias`. */
export interface Alias {
  alias: string;
  name: string | null;
}

/**
 * In-memory PKCS#12 keystore (port of `FileKeyStoreProvider` + the JDK PKCS12
 * KeyStore behaviour the library relies on). Supports legacy (RC2/3DES) and
 * modern (AES/PBES2) files and RSA or EC keys.
 */
export class KeyStore {
  private constructor(
    readonly entries: KeyEntry[],
    readonly certificates: Certificate[],
  ) {}

  static fromPkcs12(data: Uint8Array, password: string): KeyStore {
    let p12: forge.pkcs12.Pkcs12Pfx;
    // Make forge keep certificates as raw ASN.1 (never re-built from parsed fields)
    const certificateFromAsn1 = forge.pki.certificateFromAsn1;
    forge.pki.certificateFromAsn1 = () => {
      throw new Error('raw');
    };
    try {
      const asn1 = forge.asn1.fromDer(forge.util.createBuffer(Buffer.from(data).toString('binary')));
      p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
    } catch (e) {
      const msg = String((e as Error).message ?? e);
      if (/mac|password|Invalid PKCS#12|decrypt/i.test(msg)) {
        throw new RubricaException('Clave de firma incorrecta o archivo PKCS#12 dañado', { cause: e });
      }
      throw new RubricaException('No se pudo leer el archivo PKCS#12: ' + msg, { cause: e });
    } finally {
      forge.pki.certificateFromAsn1 = certificateFromAsn1;
    }

    interface RawKey {
      der: Buffer;
      localKeyId?: string;
      friendlyName?: string;
    }
    interface RawCert {
      cert: Certificate;
      localKeyId?: string;
      friendlyName?: string;
    }
    const keys: RawKey[] = [];
    const certs: RawCert[] = [];
    for (const safe of p12.safeContents) {
      for (const bag of safe.safeBags) {
        const localKeyId = bag.attributes?.localKeyId?.[0];
        const friendlyName = bag.attributes?.friendlyName?.[0];
        if (bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) {
          let der: Buffer;
          if (bag.key) {
            der = Buffer.from(
              forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(bag.key))).getBytes(),
              'binary',
            );
          } else if (bag.asn1) {
            der = Buffer.from(forge.asn1.toDer(bag.asn1).getBytes(), 'binary');
          } else {
            continue;
          }
          keys.push({ der, localKeyId, friendlyName });
        } else if (bag.type === forge.pki.oids.certBag) {
          if (!bag.asn1) continue;
          const der = Buffer.from(forge.asn1.toDer(bag.asn1).getBytes(), 'binary');
          certs.push({ cert: new Certificate(der), localKeyId, friendlyName });
        }
      }
    }

    const allCerts = certs.map((c) => c.cert);
    const entries: KeyEntry[] = [];
    keys.forEach((k, idx) => {
      const privateKey = crypto.createPrivateKey({ key: k.der, format: 'der', type: 'pkcs8' });
      const publicDer = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }) as Buffer;
      // Java matches the key with its certificate through localKeyId; fall back to the public key
      let leaf =
        (k.localKeyId !== undefined ? certs.find((c) => c.localKeyId === k.localKeyId)?.cert : undefined) ??
        allCerts.find((c) => c.subjectPublicKeyInfo.equals(publicDer));
      if (!leaf) return;
      const chain = [leaf];
      // JDK PKCS12KeyStore: follow issuer -> subject until a self signed certificate
      while (!leaf.issuer.equals(leaf.subject)) {
        const issuer = allCerts.find((c) => c.subject.equals(leaf!.issuer) && !chain.includes(c));
        if (!issuer) break;
        chain.push(issuer);
        leaf = issuer;
      }
      const alias = (k.friendlyName ?? certs.find((c) => c.cert === chain[0])?.friendlyName ?? String(idx + 1)).toLowerCase();
      entries.push({ alias, privateKey, chain, certificate: chain[0] });
    });
    if (entries.length === 0) {
      throw new AliasesNotFoundException('El archivo PKCS#12 no contiene una clave privada con su certificado');
    }
    return new KeyStore(entries, allCerts);
  }

  aliases(): string[] {
    return this.entries.map((e) => e.alias);
  }

  getEntry(alias?: string): KeyEntry {
    if (alias === undefined) return this.entries[0];
    const e = this.entries.find((x) => x.alias === alias.toLowerCase());
    if (!e) throw new AliasesNotFoundException('Alias no encontrado: ' + alias);
    return e;
  }

  /**
   * Port of `KeyStoreUtilities.getSigningAliases`: aliases whose certificate
   * has the digitalSignature key usage bit.
   */
  getSigningAliases(): Alias[] {
    const out: Alias[] = [];
    for (const e of this.entries) {
      const keyUsage = e.certificate.getKeyUsage();
      if (keyUsage !== null && keyUsage[0]) {
        out.push({ alias: e.alias, name: getCN(e.certificate) });
      }
    }
    return out;
  }
}

/** Convenience: loads a .p12/.pfx file content. */
export function loadPkcs12(data: Uint8Array, password: string): KeyStore {
  return KeyStore.fromPkcs12(data, password);
}
