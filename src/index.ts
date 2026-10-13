/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import { KeyStore } from './keystore/keystore.js';
import { PadesBasicSigner, PadesEnhancedSigner, PdfSignerOptions, SignProperties } from './pdf/pades-signer.js';
import { XAdESSigner, XadesSignOptions } from './xades/xades-signer.js';

export * from './errors.js';
export { Certificate, X500Name } from './x509/certificate.js';
export { KeyStore, loadPkcs12 } from './keystore/keystore.js';
export type { KeyEntry, Alias } from './keystore/keystore.js';
export {
  BasePdfSigner,
  PadesBasicSigner,
  PadesEnhancedSigner,
  getPositionOnPage,
  SIGNING_REASON,
  SIGNING_LOCATION,
  SIGN_TIME,
  SIGNATURE_PAGE,
  LAST_PAGE,
  FONT_SIZE,
  TYPE_SIG,
  INFO_QR,
  POSITION_ON_PAGE_LOWER_LEFT_X,
  POSITION_ON_PAGE_LOWER_LEFT_Y,
  POSITION_ON_PAGE_UPPER_RIGHT_X,
  POSITION_ON_PAGE_UPPER_RIGHT_Y,
} from './pdf/pades-signer.js';
export type { SignProperties, PdfSignerOptions, SignInfo } from './pdf/pades-signer.js';
export { XAdESSigner, COMPROBANTE_ID } from './xades/xades-signer.js';
export type { XadesSignOptions } from './xades/xades-signer.js';
export { buildCmsSignedData } from './sign/cms.js';
export type { DigestAlgorithm } from './sign/cms.js';
export { requestTimeStampToken } from './sign/tsa.js';
export type { TsaOptions } from './sign/tsa.js';
export { DatosUsuario } from './certificate/datos-usuario.js';
export { getDatosUsuarios, getNombreCA, getRootCertificate } from './certificate/cert-ec-utils.js';
export * as CertEcUtils from './certificate/cert-ec-utils.js';
export { getCN, getEmail } from './certificate/cert-utils.js';
export { CONFIG } from './utils/properties.js';

/** Visible signature types of FirmaEC (`typeSignature`). */
export type TipoFirma = 'QR' | 'information1' | 'information2';

export interface FirmarPdfOpciones extends PdfSignerOptions {
  /** Alias of the key inside the .p12 (default: the first one). */
  alias?: string;
  /**
   * Adds an RFC 3161 time stamp (`PadesEnhancedSigner`). The TSA user/password is
   * the `identificacion` property (cédula/RUC), as in FirmaEC.
   */
  selloTiempo?: boolean;
}

/**
 * Signs a PDF with a .p12/.pfx file. `propiedades` uses the same keys as the
 * Java library (signingReason, signingLocation, signTime, page, typeSignature,
 * infoQR, PositionOnPageLowerLeftX/Y, PositionOnPageUpperRightX/Y, identificacion).
 */
export async function firmarPdf(
  pdf: Uint8Array,
  p12: Uint8Array,
  clave: string,
  propiedades: SignProperties = {},
  opciones: FirmarPdfOpciones = {},
): Promise<Buffer> {
  const entry = KeyStore.fromPkcs12(p12, clave).getEntry(opciones.alias);
  const signer = opciones.selloTiempo ? new PadesEnhancedSigner(opciones) : new PadesBasicSigner(opciones);
  return signer.sign(pdf, entry.privateKey, entry.chain, propiedades);
}

/** Signs an SRI electronic document (XAdES-BES enveloped over `#comprobante`) with a .p12/.pfx file. */
export async function firmarXml(
  xml: Uint8Array | string,
  p12: Uint8Array,
  clave: string,
  opciones: XadesSignOptions & { alias?: string } = {},
): Promise<Buffer> {
  const keyStore = KeyStore.fromPkcs12(p12, clave);
  const entry = keyStore.getEntry(opciones.alias);
  const data = typeof xml === 'string' ? Buffer.from(xml, 'utf8') : xml;
  return new XAdESSigner().signWithKey(data, entry.privateKey, entry.certificate, opciones);
}
