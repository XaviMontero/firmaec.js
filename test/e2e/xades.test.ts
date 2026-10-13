/**
 * End to end: XAdES-BES (SRI) signing. Each document is signed by the original
 * Java library (EU DSS) and by the TS port; then:
 *  - DSS validates the TS signature (format, signature intact/valid, references intact),
 *  - xmlsec1 verifies it independently,
 *  - the serialized document and the signature structure are compared with DSS output.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DOMParser } from '@xmldom/xmldom';
import { InvalidFormatException, KeyStore, XAdESSigner, firmarXml } from '../../src/index.js';
import { PASSWORD, SignerFixture, signers, tmpFile } from '../helpers/fixtures.js';
import { oracle, oracleAvailable } from '../helpers/oracle.js';

interface XmlVerify {
  signatures: Array<{
    format: string;
    signatureIntact: boolean;
    signatureValid: boolean;
    signingCertificatePresent: boolean;
    digestMatchers: Array<{ type: string; found: boolean; intact: boolean }>;
  }>;
  rubricaSigners: number;
  error?: string;
}

const FACTURA = `<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.1.0">
  <infoTributaria>
    <ambiente>1</ambiente>
    <razonSocial>EMPRESA DE PRUEBA S.A.</razonSocial>
    <ruc>1790012345001</ruc>
    <claveAcceso>1210202601179001234500110010010000000011234567811</claveAcceso>
  </infoTributaria>
  <infoFactura>
    <razonSocialComprador>JOSÉ ÑÚÑEZ &amp; ASOCIADOS &lt;CIA&gt; "LTDA"</razonSocialComprador>
    <importeTotal>112.00</importeTotal>
    <vacio></vacio>
    <vacio2/>
  </infoFactura>
</factura>
`;

const DOCS: Record<string, string> = {
  factura: FACTURA,
  compacta: FACTURA.replace(/>\s+</g, '><'),
  anidado: `<?xml version="1.0" encoding="UTF-8"?><lote version="1"><cabecera>x</cabecera><comprobantes><notaCredito Id="comprobante"><dato a="1" b='2'>Ñ</dato></notaCredito></comprobantes></lote>`,
  namespaces: `<?xml version="1.0" encoding="UTF-8"?>
<f:factura xmlns:f="urn:sri:factura" xmlns="urn:default" xmlns:x="urn:x" ID="comprobante">
  <!-- comentario -->
  <detalle x:attr="v">texto <![CDATA[<cdata & más>]]> fin</detalle>
  <?pi instruccion?>
  <otro xmlns="urn:otro"><hijo/></otro>
</f:factura>`,
  crlf: FACTURA.replace(/\n/g, '\r\n'),
  atributos: `<?xml version="1.0" encoding="UTF-8"?><comprobanteRetencion id="comprobante" version="2.0.0" desc="tab&#9;nl&#10;cita&quot;amp&amp;lt&lt;"><x>&#xE1; &#233;</x></comprobanteRetencion>`,
};

function jsSign(signer: SignerFixture, xml: Buffer | string) {
  return firmarXml(xml, signer.p12, PASSWORD);
}

function javaSign(signer: SignerFixture, input: string, out: string) {
  return oracle<{ ok?: boolean; error?: string }>('sign-xml', signer.p12Path, PASSWORD, input, out);
}

function xmlsecVerify(file: string, signer: SignerFixture): boolean {
  const xml = fs.readFileSync(file, 'utf8');
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const target = (function find(n: any): any {
    if (n.nodeType === 1 && ['id', 'Id', 'ID'].some((a) => n.getAttribute(a) === 'comprobante')) return n;
    for (let c = n.firstChild; c; c = c.nextSibling) {
      const r = find(c);
      if (r) return r;
    }
    return null;
  })(doc.documentElement);
  const attr = ['id', 'Id', 'ID'].find((a) => target.getAttribute(a) === 'comprobante');
  const node = target.namespaceURI ? `${target.namespaceURI}:${target.localName}` : target.localName;
  try {
    execFileSync(
      'xmlsec1',
      [
        '--verify',
        `--id-attr:${attr}`,
        node,
        '--id-attr:Id',
        'http://uri.etsi.org/01903/v1.3.2#:SignedProperties',
        '--trusted-pem',
        signer.caPem,
        file,
      ],
      { stdio: 'pipe' },
    );
    return true;
  } catch (e) {
    console.error(String((e as { stderr?: Buffer }).stderr));
    return false;
  }
}

/** Masks the parts that legitimately change between two signatures (ids, digests, time, value). */
function signatureShape(xml: string): string {
  return xml
    .substring(xml.indexOf('<ds:Signature'))
    .replace(/id-[0-9a-f]{32}/g, 'ID')
    .replace(/<ds:DigestValue>[^<]*<\/ds:DigestValue>/g, '<ds:DigestValue/>')
    .replace(/(<ds:SignatureValue[^>]*>)[^<]*</, '$1<')
    .replace(/<xades:SigningTime>[^<]*</, '<xades:SigningTime><');
}

describe.skipIf(!oracleAvailable)('XAdES-BES e2e vs Java FirmaEC (DSS)', () => {
  for (const [label, xml] of Object.entries(DOCS)) {
    it(`${label}`, async () => {
      const input = tmpFile(`in-${label}.xml`);
      fs.writeFileSync(input, xml);
      const javaOut = tmpFile(`java-${label}.xml`);
      expect(javaSign(signers.natural, input, javaOut)).toEqual({ ok: true });
      const jsOut = tmpFile(`js-${label}.xml`);
      const signed = await jsSign(signers.natural, fs.readFileSync(input));
      fs.writeFileSync(jsOut, signed);

      const v = oracle<XmlVerify>('verify-xml', jsOut, signers.natural.caPem);
      expect(v.error).toBeUndefined();
      expect(v.rubricaSigners).toBe(1);
      expect(v.signatures).toHaveLength(1);
      expect(v.signatures[0]).toMatchObject({
        format: 'XAdES-BASELINE-B',
        signatureIntact: true,
        signatureValid: true,
        signingCertificatePresent: true,
      });
      expect(v.signatures[0].digestMatchers).toEqual([
        { type: 'REFERENCE', found: true, intact: true },
        { type: 'SIGNED_PROPERTIES', found: true, intact: true },
      ]);
      expect(xmlsecVerify(jsOut, signers.natural)).toBe(true);

      const java = fs.readFileSync(javaOut, 'utf8');
      const js = signed.toString('utf8');
      // document serialized exactly like DSS, signature with the same structure
      expect(js.substring(0, js.indexOf('<ds:Signature'))).toBe(java.substring(0, java.indexOf('<ds:Signature')));
      expect(signatureShape(js)).toBe(signatureShape(java));
    });
  }

  it('ISO-8859-1 input is re-encoded as UTF-8 like DSS', async () => {
    const latin = FACTURA.replace('encoding="UTF-8"', 'encoding="ISO-8859-1"');
    const input = tmpFile('in-latin1.xml');
    fs.writeFileSync(input, Buffer.from(latin, 'latin1'));
    const javaOut = tmpFile('java-latin1.xml');
    expect(javaSign(signers.natural, input, javaOut)).toEqual({ ok: true });
    const signed = await jsSign(signers.natural, fs.readFileSync(input));
    const jsOut = tmpFile('js-latin1.xml');
    fs.writeFileSync(jsOut, signed);
    const java = fs.readFileSync(javaOut, 'utf8');
    const js = signed.toString('utf8');
    expect(js.substring(0, js.indexOf('<ds:Signature'))).toBe(java.substring(0, java.indexOf('<ds:Signature')));
    expect(oracle<XmlVerify>('verify-xml', jsOut, signers.natural.caPem).signatures[0].signatureIntact).toBe(true);
  });

  it('legacy p12 and EC keys', async () => {
    for (const signer of [signers.legacy, signers.ec]) {
      const out = tmpFile(`xml-${signer.label}.xml`);
      fs.writeFileSync(out, await jsSign(signer, FACTURA));
      const v = oracle<XmlVerify>('verify-xml', out, signer.caPem);
      expect(v.signatures[0]).toMatchObject({ signatureIntact: true, signatureValid: true });
      expect(xmlsecVerify(out, signer)).toBe(true);
      const input = tmpFile(`in-${signer.label}.xml`);
      fs.writeFileSync(input, FACTURA);
      expect(javaSign(signer, input, tmpFile(`java-xml-${signer.label}.xml`))).toEqual({ ok: true });
    }
  });

  it('error parity: no node with id "comprobante"', async () => {
    const xml = FACTURA.replace('id="comprobante"', 'id="otro"');
    const input = tmpFile('in-noid.xml');
    fs.writeFileSync(input, xml);
    expect(javaSign(signers.natural, input, tmpFile('java-noid.xml')).error).toBeDefined();
    await expect(jsSign(signers.natural, xml)).rejects.toThrow(InvalidFormatException);
  });

  it('error parity: DOCTYPE is rejected (secure parsing)', async () => {
    const xml = FACTURA.replace('<factura', '<!DOCTYPE factura [<!ENTITY e "x">]>\n<factura');
    const input = tmpFile('in-doctype.xml');
    fs.writeFileSync(input, xml);
    expect(javaSign(signers.natural, input, tmpFile('java-doctype.xml')).error).toBeDefined();
    await expect(jsSign(signers.natural, xml)).rejects.toThrow(InvalidFormatException);
  });

  it('error parity: malformed XML', async () => {
    const input = tmpFile('in-bad.xml');
    fs.writeFileSync(input, '<factura id="comprobante"><a></factura>');
    expect(javaSign(signers.natural, input, tmpFile('java-bad.xml')).error).toBeDefined();
    await expect(jsSign(signers.natural, '<factura id="comprobante"><a></factura>')).rejects.toThrow(InvalidFormatException);
  });

  it('XAdESSigner.sign(data, keyStore, clave) uses the first key entry like Java', async () => {
    const ks = KeyStore.fromPkcs12(signers.natural.p12, PASSWORD);
    const out = tmpFile('xml-api.xml');
    fs.writeFileSync(out, await new XAdESSigner().sign(Buffer.from(FACTURA), ks, PASSWORD));
    expect(oracle<XmlVerify>('verify-xml', out, signers.natural.caPem).signatures[0].signatureValid).toBe(true);
  });
});
