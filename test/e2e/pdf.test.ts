/**
 * End to end: PAdES signing. Every case is signed by the original Java library
 * (oracle) and by the TS port with the same inputs, then:
 *  - iText (Java) verifies the TS signature (integrity + covers whole document),
 *  - poppler `pdfsig` and `qpdf --check` validate the TS output,
 *  - signature dictionary, widget and the visible layer (text, positions, glyphs,
 *    QR content) of both outputs are compared.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { KeyStore } from '../../src/keystore/keystore.js';
import { PadesBasicSigner } from '../../src/pdf/pades-signer.js';
import { EntidadCertificadoraNoValidaException, InvalidFormatException, RubricaException, firmarPdf } from '../../src/index.js';
import { DocFixture, PASSWORD, SignerFixture, pdfDocs, signers, tmpFile, writeProps } from '../helpers/fixtures.js';
import { oracle, oracleAvailable } from '../helpers/oracle.js';
import { SignatureField, inspectSignatures } from '../helpers/pdf-inspect.js';

interface VerifyResult {
  signatures: Array<{
    name: string;
    integrity: boolean;
    coversWholeDocument: boolean;
    revision: number;
    signer: string;
    chainLength: number;
    digestAlgorithm: string;
    signDate: string;
    reason: string;
    location: string;
    filter: string;
  }>;
  pages: number;
  rubricaSigners: number;
  error?: string;
}

const SIGN_TIME = '2026-10-12T10:15:30-05:00';

const CASES: Record<string, Record<string, string | number>> = {
  qr: {
    signingReason: 'Aprobación del contrato N° 123',
    signingLocation: 'Quito',
    signTime: SIGN_TIME,
    page: 1,
    typeSignature: 'QR',
    infoQR: 'Validar en https://www.firmadigital.gob.ec',
    PositionOnPageLowerLeftX: 100,
    PositionOnPageLowerLeftY: 150,
  },
  qrBig: {
    signingReason: 'Motivo',
    signingLocation: 'Guayaquil',
    signTime: SIGN_TIME,
    typeSignature: 'QR',
    PositionOnPageLowerLeftX: 40,
    PositionOnPageLowerLeftY: 300,
    PositionOnPageUpperRightX: 220,
    PositionOnPageUpperRightY: 70,
  },
  information1: {
    signingReason: 'Motivo largo de la firma, con comas y acentos: á é í ó ú ñ',
    signingLocation: 'Guayaquil',
    signTime: SIGN_TIME,
    page: 2,
    typeSignature: 'information1',
    PositionOnPageLowerLeftX: 50,
    PositionOnPageLowerLeftY: 700,
    PositionOnPageUpperRightX: 250,
    PositionOnPageUpperRightY: 60,
  },
  information2: {
    signingReason: 'Revisado',
    signingLocation: 'Cuenca',
    signTime: SIGN_TIME,
    page: 99, // out of range -> last page
    typeSignature: 'information2',
    PositionOnPageLowerLeftX: 300,
    PositionOnPageLowerLeftY: 200,
  },
  invisible: { signingReason: 'No se muestra', signingLocation: 'Loja', signTime: SIGN_TIME },
};

function verify(file: string): VerifyResult {
  return oracle<VerifyResult>('verify-pdf', file);
}

function javaSign(signer: SignerFixture, input: string, out: string, props: Record<string, string | number>) {
  return oracle<{ ok?: boolean; error?: string }>('sign-pdf', signer.p12Path, PASSWORD, input, out, writeProps(out, props));
}

async function jsSign(signer: SignerFixture, input: Uint8Array, props: Record<string, string | number>) {
  const e = KeyStore.fromPkcs12(signer.p12, PASSWORD).getEntry();
  return new PadesBasicSigner().sign(input, e.privateKey, e.chain, props);
}

function pdfsigValid(file: string): number {
  const out = execFileSync('pdfsig', [file], { encoding: 'utf8' });
  return (out.match(/Signature is Valid/g) ?? []).length;
}

function qpdfOk(file: string): boolean {
  try {
    execFileSync('qpdf', ['--check', file], { encoding: 'utf8' });
    return true;
  } catch (e) {
    // exit code 3 = warnings only
    return (e as { status?: number }).status === 3;
  }
}

/** Visible output must match iText (positions to the hundredth of a point). */
function expectSameField(js: SignatureField, java: SignatureField) {
  expect(js.name).toBe(java.name);
  expect(js.page).toBe(java.page);
  expect(js.rect).toEqual(java.rect);
  expect(js.flags).toBe(java.flags);
  expect(js.fieldType).toBe(java.fieldType);
  expect(js.dict).toEqual(java.dict);
  expect(js.text.map((l) => [l.font, l.size, l.glyphs])).toEqual(java.text.map((l) => [l.font, l.size, l.glyphs]));
  js.text.forEach((l, i) => {
    expect(Math.abs(l.x - java.text[i].x), `x line ${i}`).toBeLessThanOrEqual(0.011);
    expect(Math.abs(l.y - java.text[i].y), `y line ${i}`).toBeLessThanOrEqual(0.011);
  });
  expect(js.images.map((i) => i.matrix)).toEqual(java.images.map((i) => i.matrix));
  expect(js.qr).toBe(java.qr);
}

describe.skipIf(!oracleAvailable)('PAdES e2e vs Java FirmaEC', () => {
  let docs: DocFixture[];
  beforeAll(async () => {
    docs = await pdfDocs();
  });

  for (const docLabel of ['simple', 'objstm', 'acroform']) {
    for (const [caseLabel, props] of Object.entries(CASES)) {
      it(`${docLabel} / ${caseLabel}`, async () => {
        const doc = docs.find((d) => d.label === docLabel)!;
        const javaOut = tmpFile(`java-${docLabel}-${caseLabel}.pdf`);
        expect(javaSign(signers.natural, doc.path, javaOut, props)).toEqual({ ok: true });
        const jsOut = tmpFile(`js-${docLabel}-${caseLabel}.pdf`);
        const signed = await jsSign(signers.natural, doc.bytes, props);
        fs.writeFileSync(jsOut, signed);

        // original bytes untouched (append mode)
        expect(signed.subarray(0, doc.bytes.length).equals(doc.bytes)).toBe(true);

        const vJs = verify(jsOut);
        const vJava = verify(javaOut);
        expect(vJs.error).toBeUndefined();
        expect(vJs.signatures).toHaveLength(1);
        const [s] = vJs.signatures;
        expect(s.integrity).toBe(true);
        expect(s.coversWholeDocument).toBe(true);
        expect({ ...s }).toEqual({ ...vJava.signatures[0] });
        expect(vJs.rubricaSigners).toBe(1);

        expect(pdfsigValid(jsOut)).toBe(1);
        expect(qpdfOk(jsOut)).toBe(true);

        const [fJs] = await inspectSignatures(signed);
        const [fJava] = await inspectSignatures(fs.readFileSync(javaOut));
        expectSameField(fJs, fJava);
        if (props.typeSignature) expect(fJs.text.length).toBeGreaterThan(0);
        if (props.typeSignature === 'QR') expect(fJs.qr).toContain('FIRMADO POR: JOS? MAR?A P?REZ ?AND?');
      });
    }
  }

  it('visible names: truncation, wrapping and razón social match Java', async () => {
    const doc = docs[0];
    for (const [signer, typeSignature] of [
      [signers.longName, 'QR'],
      [signers.longName, 'information1'],
      [signers.longName, 'information2'],
      [signers.sello, 'QR'],
      [signers.sello, 'information2'],
    ] as const) {
      const props = { ...CASES.qr, typeSignature };
      const javaOut = tmpFile(`java-name-${signer.label}-${typeSignature}.pdf`);
      expect(javaSign(signer, doc.path, javaOut, props)).toEqual({ ok: true });
      const signed = await jsSign(signer, doc.bytes, props);
      const [fJs] = await inspectSignatures(signed);
      const [fJava] = await inspectSignatures(fs.readFileSync(javaOut));
      expectSameField(fJs, fJava);
    }
  });

  it('multiple signatures interoperate (Java -> TS -> Java -> TS)', async () => {
    let current = docs[0].path;
    const order = ['java', 'js', 'java', 'js'] as const;
    for (let i = 0; i < order.length; i++) {
      const props = { ...CASES.qr, PositionOnPageLowerLeftX: 40 + i * 120 };
      const out = tmpFile(`multi-${i}.pdf`);
      if (order[i] === 'java') {
        expect(javaSign(signers.natural, current, out, props)).toEqual({ ok: true });
      } else {
        fs.writeFileSync(out, await jsSign(signers.natural, fs.readFileSync(current), props));
      }
      current = out;
    }
    const v = verify(current);
    expect(v.signatures.map((s) => s.name)).toEqual(['Signature1', 'Signature2', 'Signature3', 'Signature4']);
    expect(v.signatures.every((s) => s.integrity)).toBe(true);
    expect(v.signatures.map((s) => s.coversWholeDocument)).toEqual([false, false, false, true]);
    expect(v.signatures.map((s) => s.revision)).toEqual([1, 2, 3, 4]);
    expect(pdfsigValid(current)).toBe(4);
    expect(qpdfOk(current)).toBe(true);
  });

  it('legacy (3DES/RC2) p12 and EC keys', async () => {
    for (const signer of [signers.legacy, signers.ec]) {
      const out = tmpFile(`keys-${signer.label}.pdf`);
      fs.writeFileSync(out, await jsSign(signer, docs[0].bytes, CASES.qr));
      const v = verify(out);
      expect(v.signatures[0].integrity).toBe(true);
      expect(v.signatures[0].coversWholeDocument).toBe(true);
      expect(pdfsigValid(out)).toBe(1);
    }
    // Java signs with the legacy p12 too...
    expect(javaSign(signers.legacy, docs[0].path, tmpFile('keys-java-legacy.pdf'), CASES.qr)).toEqual({ ok: true });
    // ...but the original library only supports RSA keys (the port also signs with EC keys)
    expect(javaSign(signers.ec, docs[0].path, tmpFile('keys-java-ec.pdf'), CASES.qr).error).toMatch(/Unsupported algorithm: EC/);
  });

  it('error parity: visible signature without position', async () => {
    const props = { signTime: SIGN_TIME, typeSignature: 'QR' };
    expect(javaSign(signers.natural, docs[0].path, tmpFile('err-nopos.pdf'), props).error).toMatch(/NullPointerException/);
    await expect(jsSign(signers.natural, docs[0].bytes, props)).rejects.toThrow(RubricaException);
  });

  it('error parity: non integer position is ignored -> no rectangle -> failure', async () => {
    const props = { ...CASES.qr, PositionOnPageLowerLeftX: '10.5' };
    expect(javaSign(signers.natural, docs[0].path, tmpFile('err-dec.pdf'), props).error).toBeDefined();
    await expect(jsSign(signers.natural, docs[0].bytes, props)).rejects.toThrow(RubricaException);
  });

  it('error parity: unknown CA fails for visible signatures but signs invisibly', async () => {
    expect(javaSign(signers.unknown, docs[0].path, tmpFile('err-unknown.pdf'), CASES.qr).error).toMatch(/NullPointerException/);
    await expect(jsSign(signers.unknown, docs[0].bytes, CASES.qr)).rejects.toThrow(EntidadCertificadoraNoValidaException);

    const javaOut = tmpFile('unknown-invisible-java.pdf');
    expect(javaSign(signers.unknown, docs[0].path, javaOut, CASES.invisible)).toEqual({ ok: true });
    const jsOut = tmpFile('unknown-invisible-js.pdf');
    fs.writeFileSync(jsOut, await jsSign(signers.unknown, docs[0].bytes, CASES.invisible));
    expect(verify(jsOut).signatures[0].integrity).toBe(true);
    expectSameField((await inspectSignatures(fs.readFileSync(jsOut)))[0], (await inspectSignatures(fs.readFileSync(javaOut)))[0]);
  });

  it('error parity: invalid typeSignature', async () => {
    const props = { ...CASES.qr, typeSignature: 'otro' };
    expect(javaSign(signers.natural, docs[0].path, tmpFile('err-type.pdf'), props).error).toMatch(/typeSign unknown/);
    await expect(jsSign(signers.natural, docs[0].bytes, props)).rejects.toThrow('typeSign unknown');
  });

  it('rejects non PDF input and wrong passwords', async () => {
    await expect(jsSign(signers.natural, Buffer.from('no soy un pdf'), CASES.qr)).rejects.toThrow(InvalidFormatException);
    await expect(firmarPdf(docs[0].bytes, signers.natural.p12, 'mala', CASES.qr)).rejects.toThrow(/Clave de firma incorrecta/);
  });

  it('firmarPdf convenience API', async () => {
    const out = tmpFile('api.pdf');
    fs.writeFileSync(out, await firmarPdf(docs[0].bytes, signers.natural.p12, PASSWORD, CASES.information1));
    expect(verify(out).signatures[0].integrity).toBe(true);
  });
});
