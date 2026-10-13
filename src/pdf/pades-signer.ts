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
import { PDFArray, PDFDict, PDFName, PDFRef, PDFString, PDFHexString, PDFNumber } from 'pdf-lib';
import { getDatosUsuarios } from '../certificate/cert-ec-utils.js';
import { EntidadCertificadoraNoValidaException, RubricaException, TsaException } from '../errors.js';
import { DigestAlgorithm, buildCmsSignedData, digest } from '../sign/cms.js';
import { TsaHttpError, requestTimeStampToken } from '../sign/tsa.js';
import { CONFIG, parseJavaInt, parseSignTime } from '../utils/properties.js';
import { Certificate } from '../x509/certificate.js';
import {
  AppearanceStream,
  CustomAppearance,
  Information1Appearance,
  Information2Appearance,
  QrAppearance,
  Rect,
  buildAppearanceXObjects,
} from './appearance.js';
import { IncrementalPdf } from './incremental.js';
import { pdfDate, pdfName, pdfTextString } from './pdf-strings.js';

/** Property keys of `BasePdfSigner` / `RectanguloUtil` (same names as in Java). */
export const SIGNING_REASON = 'signingReason';
export const SIGNING_LOCATION = 'signingLocation';
export const SIGN_TIME = 'signTime';
export const SIGNATURE_PAGE = 'signingPage';
export const LAST_PAGE = 'page';
export const FONT_SIZE = 'font';
export const TYPE_SIG = 'typeSignature';
export const INFO_QR = 'infoQR';
export const POSITION_ON_PAGE_LOWER_LEFT_X = 'PositionOnPageLowerLeftX';
export const POSITION_ON_PAGE_LOWER_LEFT_Y = 'PositionOnPageLowerLeftY';
export const POSITION_ON_PAGE_UPPER_RIGHT_X = 'PositionOnPageUpperRightX';
export const POSITION_ON_PAGE_UPPER_RIGHT_Y = 'PositionOnPageUpperRightY';

/** Java `Properties` equivalent: string values (numbers accepted for convenience). */
export type SignProperties = Record<string, string | number | null | undefined>;

/** Size of the /Contents placeholder in bytes (`signExternalContainer(external, 8192 * 2)`). */
const ESTIMATED_SIZE = 8192 * 2;

function prop(p: SignProperties | undefined, key: string): string | null {
  const v = p?.[key];
  return v === undefined || v === null ? null : String(v);
}

/** Port of `RectanguloUtil.getPositionOnPage`. NOTE: "UpperRight" values are width/height (iText Rectangle). */
export function getPositionOnPage(extraParams: SignProperties | undefined): Rect | null {
  if (!extraParams) return null;
  const llx = prop(extraParams, POSITION_ON_PAGE_LOWER_LEFT_X);
  const lly = prop(extraParams, POSITION_ON_PAGE_LOWER_LEFT_Y);
  const urx = prop(extraParams, POSITION_ON_PAGE_UPPER_RIGHT_X);
  const ury = prop(extraParams, POSITION_ON_PAGE_UPPER_RIGHT_Y);
  if (llx !== null && lly !== null && urx !== null && ury !== null) {
    try {
      return {
        x: parseJavaInt(llx.trim()),
        y: parseJavaInt(lly.trim()),
        width: parseJavaInt(urx.trim()),
        height: parseJavaInt(ury.trim()),
      };
    } catch {
      // "Se ha indicado una posicion invalida para la firma"
    }
  }
  if (llx !== null && lly !== null && urx === null && ury === null) {
    try {
      return { x: parseJavaInt(llx.trim()), y: parseJavaInt(lly.trim()) - 36, width: 110, height: 36 };
    } catch {
      // posicion invalida
    }
  }
  return null;
}

/** Port of `sign.SignInfo`. */
export interface SignInfo {
  certificados: Certificate[];
  fechaFirma: Date;
}

export interface PdfSignerOptions {
  /** Digest of the signature (FirmaEC uses SHA-256). */
  digestAlgorithm?: DigestAlgorithm;
  /**
   * Timezone offset (minutes east of UTC) for the PDF /M date; defaults to the
   * process timezone, like the JVM default timezone in Java.
   */
  timeZoneOffsetMinutes?: number;
  /** Clock used when no signTime is given (tests). */
  now?: () => Date;
  /** Custom fetch for the TSA (tests / proxies). */
  fetch?: typeof fetch;
  /** TSA url for the enhanced signer (Java: `tsa_url` in config.rubrica.properties). */
  tsaUrl?: string;
}

interface PreparedSignature {
  bytes: Buffer;
  byteRange: [number, number, number, number];
  contentsStart: number;
  contentsEnd: number;
  fieldName: string;
}

/**
 * Port of `sign.pdf.BasePdfSigner`: prepares the PDF in append mode with an empty
 * signature dictionary (`emptySignature`) and inserts the CMS (`createSignature`).
 */
export abstract class BasePdfSigner {
  protected readonly digestAlgorithm: DigestAlgorithm;

  constructor(protected readonly options: PdfSignerOptions = {}) {
    this.digestAlgorithm = options.digestAlgorithm ?? 'SHA256';
  }

  /** Signs the PDF. `certificates[0]` is the signer certificate. */
  async sign(
    pdf: Uint8Array,
    privateKey: crypto.KeyObject,
    certificates: Certificate[],
    properties: SignProperties = {},
  ): Promise<Buffer> {
    const prepared = await this.emptySignature(pdf, certificates, properties);
    const contentDigest = digest(
      this.digestAlgorithm,
      prepared.bytes.subarray(prepared.byteRange[0], prepared.byteRange[0] + prepared.byteRange[1]),
      prepared.bytes.subarray(prepared.byteRange[2], prepared.byteRange[2] + prepared.byteRange[3]),
    );
    const cms = await this.signedHash(contentDigest, privateKey, certificates, properties);
    return this.createSignature(prepared, cms);
  }

  /** Builds the CMS container for the document digest (the `signed_hash` of the Java signers). */
  protected abstract signedHash(
    hash: Buffer,
    privateKey: crypto.KeyObject,
    chain: Certificate[],
    properties: SignProperties,
  ): Promise<Buffer>;

  /** Port of `emptySignature`. */
  async emptySignature(input: Uint8Array, certChain: Certificate[], properties: SignProperties): Promise<PreparedSignature> {
    const pdf = await IncrementalPdf.load(input);
    const { doc, context } = pdf;
    const x509Certificate = certChain[0];
    const extraParams = properties ?? {};

    const reason = prop(extraParams, SIGNING_REASON);
    const location = prop(extraParams, SIGNING_LOCATION);
    const signTime = prop(extraParams, SIGN_TIME);
    const typeSig = prop(extraParams, TYPE_SIG);
    const infoQR = prop(extraParams, INFO_QR) === null ? '' : prop(extraParams, INFO_QR)!.trim();

    const pages = doc.getPages();
    let page = 0;
    const pageProp = prop(extraParams, LAST_PAGE);
    if (pageProp !== null) {
      try {
        page = parseJavaInt(pageProp.trim());
      } catch {
        page = 0;
      }
    }
    if (page === 0 || page < 0 || page > pages.length) page = pages.length;
    const pageObj = pages[page - 1];

    const signaturePositionOnPage = getPositionOnPage(extraParams);
    let rect: Rect = { x: 0, y: 0, width: 0, height: 0 };
    let layer2: AppearanceStream | null = null;
    let sigReason = '';
    let sigLocation = '';
    let creator = '';

    if (typeSig !== null) {
      if (signaturePositionOnPage === null) {
        // Java: PdfSignatureAppearance.setPageRect(null) -> NullPointerException
        throw new RubricaException('Posición de la firma visible no indicada o inválida');
      }
      rect = signaturePositionOnPage;
      let datosUsuario = null;
      try {
        datosUsuario = getDatosUsuarios(x509Certificate);
      } catch (e) {
        if (!(e instanceof EntidadCertificadoraNoValidaException)) throw e;
      }
      if (datosUsuario === null) {
        // Java dereferences the null DatosUsuario (NullPointerException)
        throw new EntidadCertificadoraNoValidaException(
          'Entidad Certificadora no reconocida: no se pueden obtener los datos del firmante para la firma visible',
        );
      }
      let nombreFirmante = '';
      if (datosUsuario.getCedula() !== null) {
        nombreFirmante = datosUsuario.getNombre() + ' ' + datosUsuario.getApellido();
      } else {
        nombreFirmante = nombreFirmante + datosUsuario.getRazonSocial();
      }
      nombreFirmante = nombreFirmante.toUpperCase();
      const informacionCertificado = x509Certificate.subjectPrincipal;
      let appearance: CustomAppearance;
      switch (typeSig) {
        case 'QR':
          appearance = new QrAppearance({ nombreFirmante, reason, location, signTime, infoQR });
          break;
        case 'information1':
          appearance = new Information1Appearance({ nombreFirmante, reason, location, signTime });
          break;
        case 'information2':
          appearance = new Information2Appearance({ nombreFirmante, informacionCertificado, reason, location, signTime });
          break;
        default:
          throw new RubricaException('typeSign unknown');
      }
      layer2 = await appearance.createLayer2(doc, rect);
      if (reason !== null) sigReason = reason;
      if (location !== null) sigLocation = location;
      creator = CONFIG.version + ' (FirmaEC)';
    }

    let signDate = (this.options.now ?? (() => new Date()))();
    if (signTime !== null) {
      signDate = parseSignTime(signTime) ?? new Date();
    }

    // ---- AcroForm and field
    const catalog = doc.catalog;
    let acroForm: PDFDict;
    const acroFormEntry = catalog.get(PDFName.of('AcroForm'));
    if (acroFormEntry instanceof PDFRef) {
      acroForm = context.lookup(acroFormEntry, PDFDict);
      pdf.markChanged(acroFormEntry);
    } else if (acroFormEntry instanceof PDFDict) {
      acroForm = acroFormEntry;
      pdf.markChanged(context.trailerInfo.Root as PDFRef);
    } else {
      acroForm = context.obj({});
      catalog.set(PDFName.of('AcroForm'), context.register(acroForm));
      pdf.markChanged(context.trailerInfo.Root as PDFRef);
    }
    let fields: PDFArray;
    const fieldsEntry = acroForm.get(PDFName.of('Fields'));
    if (fieldsEntry instanceof PDFRef) {
      fields = context.lookup(fieldsEntry, PDFArray);
      pdf.markChanged(fieldsEntry);
    } else if (fieldsEntry instanceof PDFArray) {
      fields = fieldsEntry;
    } else {
      fields = context.obj([]);
      acroForm.set(PDFName.of('Fields'), fields);
    }
    const fieldName = newSigFieldName(context, fields);

    const sigRef = pdf.reserveRaw();
    const apRef = buildAppearanceXObjects(doc, rect, layer2);
    layer2?.fontObjects.forEach((f) => f.embed());

    const widget = context.obj({
      AP: { N: apRef },
      F: 132,
      FT: 'Sig',
      H: 'N',
      P: pageObj.ref,
      Rect: [rect.x, rect.y, rect.x + rect.width, rect.y + rect.height],
      Subtype: 'Widget',
      T: PDFString.of(fieldName),
      V: sigRef,
    });
    const widgetRef = context.register(widget);
    fields.push(widgetRef);
    acroForm.set(PDFName.of('SigFlags'), PDFNumber.of(3));

    const annots = pageObj.node.get(PDFName.of('Annots'));
    if (annots instanceof PDFRef) {
      context.lookup(annots, PDFArray).push(widgetRef);
      pdf.markChanged(annots);
    } else if (annots instanceof PDFArray) {
      annots.push(widgetRef);
      pdf.markChanged(pageObj.ref);
    } else {
      pageObj.node.set(PDFName.of('Annots'), context.obj([widgetRef]));
      pdf.markChanged(pageObj.ref);
    }

    // ---- signature dictionary with placeholders
    const byteRangePlaceholder = '[0 ********** ********** **********]';
    const contentsPlaceholder = '<' + '0'.repeat(ESTIMATED_SIZE * 2) + '>';
    const sigDict =
      '<</ByteRange ' +
      byteRangePlaceholder +
      ' /ContactInfo() /Contents ' +
      contentsPlaceholder +
      ' /Filter /Adobe.PPKLite /Location ' +
      pdfTextString(sigLocation) +
      ' /M ' +
      pdfTextString(pdfDate(signDate, this.options.timeZoneOffsetMinutes)) +
      ' /Prop_Build <</App <</Name ' +
      pdfName(creator) +
      '>>>> /Reason ' +
      pdfTextString(sigReason) +
      ' /SubFilter /adbe.pkcs7.detached /Type /Sig>>';
    pdf.setRaw(sigRef, Buffer.from(sigDict, 'latin1'));

    const { bytes, offsets } = pdf.build();
    const sigOffset = offsets.get(sigRef.objectNumber)!;
    const contentsStart = bytes.indexOf(contentsPlaceholder, sigOffset, 'latin1');
    const contentsEnd = contentsStart + contentsPlaceholder.length;
    const byteRange: [number, number, number, number] = [0, contentsStart, contentsEnd, bytes.length - contentsEnd];
    const brStart = bytes.indexOf(byteRangePlaceholder, sigOffset, 'latin1');
    const brText = `[${byteRange.join(' ')}]`.padEnd(byteRangePlaceholder.length, ' ');
    if (brText.length > byteRangePlaceholder.length) throw new RubricaException('ByteRange demasiado grande');
    bytes.write(brText, brStart, 'latin1');
    return { bytes, byteRange, contentsStart, contentsEnd, fieldName };
  }

  /** Port of `createSignature` (`PdfSigner.signDeferred`): writes the CMS into /Contents. */
  createSignature(prepared: PreparedSignature, cms: Buffer): Buffer {
    const hex = cms.toString('hex');
    if (hex.length > ESTIMATED_SIZE * 2) throw new RubricaException('Not enough space');
    const out = Buffer.from(prepared.bytes);
    out.write(hex, prepared.contentsStart + 1, 'latin1');
    return out;
  }
}

/** iText `PdfSigner.getNewSigFieldName`: "Signature" + first free index. */
function newSigFieldName(context: IncrementalPdf['context'], fields: PDFArray): string {
  const names = new Set<string>();
  const walk = (arr: PDFArray, prefix: string) => {
    for (let i = 0; i < arr.size(); i++) {
      const f = context.lookupMaybe(arr.get(i), PDFDict);
      if (!f) continue;
      const t = f.get(PDFName.of('T'));
      const partial = t instanceof PDFString || t instanceof PDFHexString ? t.decodeText() : null;
      const full = partial === null ? prefix : prefix ? `${prefix}.${partial}` : partial;
      if (full) names.add(full);
      const kids = context.lookupMaybe(f.get(PDFName.of('Kids')), PDFArray);
      if (kids) walk(kids, full);
    }
  };
  walk(fields, '');
  let step = 1;
  while (names.has('Signature' + step)) step++;
  return 'Signature' + step;
}

/** Port of `sign.pdf.PadesBasicSigner`: PAdES basic (adbe.pkcs7.detached), no time stamp. */
export class PadesBasicSigner extends BasePdfSigner {
  protected async signedHash(hash: Buffer, privateKey: crypto.KeyObject, chain: Certificate[]): Promise<Buffer> {
    return buildCmsSignedData({ digestAlgorithm: this.digestAlgorithm, chain, privateKey, contentDigest: hash });
  }
}

/**
 * Port of `sign.pdf.PadesEnhancedSigner`: adds an RFC 3161 time stamp from the
 * FirmaEC TSA, authenticated with the signer identification (cédula/RUC) as
 * user and password, when the `identificacion` property is present.
 */
export class PadesEnhancedSigner extends BasePdfSigner {
  protected async signedHash(
    hash: Buffer,
    privateKey: crypto.KeyObject,
    chain: Certificate[],
    properties: SignProperties,
  ): Promise<Buffer> {
    const identificacion = prop(properties, 'identificacion');
    const tsaUrl = this.options.tsaUrl ?? CONFIG.tsa_url;
    const timestamp =
      identificacion !== null && identificacion !== ''
        ? (signatureValue: Buffer) =>
            requestTimeStampToken(signatureValue, {
              url: tsaUrl,
              username: identificacion,
              password: identificacion,
              fetch: this.options.fetch,
              timeoutMs: CONFIG.time_out,
            })
        : undefined;
    try {
      return await buildCmsSignedData({ digestAlgorithm: this.digestAlgorithm, chain, privateKey, contentDigest: hash, timestamp });
    } catch (e) {
      if (e instanceof TsaHttpError) {
        if (e.status === 401) {
          throw new TsaException(
            'Error de autenticación TSA (sello de tiempo): Las credenciales proporcionadas son incorrectas. Verifique usuario y contraseña.',
            { cause: e },
          );
        }
        if (e.status === 409) {
          throw new TsaException(
            'Error de conflicto TSA (sello de tiempo): No se puede obtener el sello de tiempo debido a un conflicto. El hash podría estar duplicado.',
            { cause: e },
          );
        }
        throw new TsaException(
          `Error del servidor TSA (sello de tiempo) (HTTP ${e.status}): No se pudo obtener el sello de tiempo. URL: ${tsaUrl}`,
          { cause: e },
        );
      }
      if (timestamp) {
        throw new TsaException('Error al obtener TSA (sello de tiempo): ' + (e as Error).message, { cause: e });
      }
      throw e;
    }
  }
}
