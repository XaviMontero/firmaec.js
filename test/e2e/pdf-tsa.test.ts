/**
 * End to end: PadesEnhancedSigner (RFC 3161 time stamp). A local TSA (openssl ts)
 * with basic auth stands in for tsa.uanatacaec.com; both the Java library and
 * the TS port sign against it and iText verifies the time stamps.
 */
import fs from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { KeyStore } from '../../src/keystore/keystore.js';
import { PadesEnhancedSigner } from '../../src/pdf/pades-signer.js';
import { TsaException, firmarPdf } from '../../src/index.js';
import { PASSWORD, pdfDocs, signers, tmpFile, writeProps, DocFixture } from '../helpers/fixtures.js';
import { oracle, oracleAsync, oracleAvailable } from '../helpers/oracle.js';
import { TsaServer, startTsa } from '../helpers/tsa-server.js';

const ID = '1712345678';
const props = {
  signingReason: 'Con sello de tiempo',
  signingLocation: 'Quito',
  signTime: '2026-10-12T10:15:30-05:00',
  typeSignature: 'QR',
  PositionOnPageLowerLeftX: 100,
  PositionOnPageLowerLeftY: 150,
  identificacion: ID,
};

interface Verify {
  signatures: Array<{ integrity: boolean; coversWholeDocument: boolean; timestamp: boolean; timestampImprint: boolean }>;
}

describe.skipIf(!oracleAvailable)('PAdES with time stamp (TSA) vs Java FirmaEC', () => {
  let tsa: TsaServer;
  let doc: DocFixture;
  beforeAll(async () => {
    tsa = await startTsa({ user: ID, password: ID });
    doc = (await pdfDocs())[0];
  });
  afterAll(async () => {
    await tsa.close();
  });

  it('TS signature carries a valid RFC 3161 time stamp (verified by iText)', async () => {
    const e = KeyStore.fromPkcs12(signers.natural.p12, PASSWORD).getEntry();
    const out = tmpFile('tsa-js.pdf');
    fs.writeFileSync(out, await new PadesEnhancedSigner({ tsaUrl: tsa.url }).sign(doc.bytes, e.privateKey, e.chain, props));
    const v = oracle<Verify>('verify-pdf', out);
    expect(v.signatures[0]).toMatchObject({ integrity: true, coversWholeDocument: true, timestamp: true, timestampImprint: true });
    // TSA called with basic auth user = password = identificacion
    expect(tsa.requests.at(-1)?.authorization).toBe('Basic ' + Buffer.from(`${ID}:${ID}`).toString('base64'));
  });

  it('Java signature against the same TSA verifies the same way', async () => {
    const out = tmpFile('tsa-java.pdf');
    expect(await oracleAsync('sign-pdf-enhanced', signers.natural.p12Path, PASSWORD, doc.path, out, writeProps(out, props), tsa.url)).toEqual({
      ok: true,
    });
    const v = oracle<Verify>('verify-pdf', out);
    expect(v.signatures[0]).toMatchObject({ integrity: true, timestamp: true, timestampImprint: true });
  });

  it('wrong credentials: same 401 message as Java', async () => {
    const bad = { ...props, identificacion: '0999999999' };
    const out = tmpFile('tsa-401-java.pdf');
    const java = await oracleAsync<{ error?: string }>('sign-pdf-enhanced', signers.natural.p12Path, PASSWORD, doc.path, out, writeProps(out, bad), tsa.url);
    const expected = 'Error de autenticación TSA (sello de tiempo): Las credenciales proporcionadas son incorrectas. Verifique usuario y contraseña.';
    expect(java.error).toContain(expected);
    await expect(firmarPdf(doc.bytes, signers.natural.p12, PASSWORD, bad, { selloTiempo: true, tsaUrl: tsa.url })).rejects.toThrow(
      new TsaException(expected),
    );
  });

  it('other HTTP errors are reported like Java', async () => {
    const broken = await startTsa({ status: 503 });
    try {
      await expect(firmarPdf(doc.bytes, signers.natural.p12, PASSWORD, props, { selloTiempo: true, tsaUrl: broken.url })).rejects.toThrow(
        `Error del servidor TSA (sello de tiempo) (HTTP 503): No se pudo obtener el sello de tiempo. URL: ${broken.url}`,
      );
    } finally {
      await broken.close();
    }
  });

  it('without identificacion no time stamp is requested', async () => {
    const before = tsa.requests.length;
    const out = tmpFile('tsa-none.pdf');
    const { identificacion: _, ...noId } = props;
    fs.writeFileSync(out, await firmarPdf(doc.bytes, signers.natural.p12, PASSWORD, noId, { selloTiempo: true, tsaUrl: tsa.url }));
    expect(tsa.requests.length).toBe(before);
    expect(oracle<Verify>('verify-pdf', out).signatures[0]).toMatchObject({ integrity: true, timestamp: false });
  });
});
