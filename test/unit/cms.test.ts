import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseDer } from '../../src/asn1/der.js';
import { KeyStore } from '../../src/keystore/keystore.js';
import { buildCmsSignedData } from '../../src/sign/cms.js';
import { PASSWORD, pdfDocs, signers, tmpFile, writeProps } from '../helpers/fixtures.js';
import { oracle, oracleAvailable } from '../helpers/oracle.js';

describe.skipIf(!oracleAvailable)('CMS container', () => {
  it('is byte for byte identical to iText PdfPKCS7 for the same document digest', async () => {
    const [doc] = await pdfDocs();
    const out = tmpFile('cms-java.pdf');
    expect(oracle('sign-pdf', signers.natural.p12Path, PASSWORD, doc.path, out, writeProps(out, { signTime: '2026-10-12T10:15:30-05:00' }))).toEqual({ ok: true });
    const pdf = fs.readFileSync(out).toString('latin1');
    const hex = /\/Contents\s*<([0-9a-fA-F]+)>/.exec(pdf)![1];
    const javaCms = parseDer(Buffer.from(hex, 'hex'), false).raw;
    // messageDigest attribute value
    const h = javaCms.toString('hex');
    const i = h.indexOf('06092a864886f70d01090431220420');
    const contentDigest = Buffer.from(h.substring(i + 30, i + 94), 'hex');
    const e = KeyStore.fromPkcs12(signers.natural.p12, PASSWORD).getEntry();
    const ours = await buildCmsSignedData({ digestAlgorithm: 'SHA256', chain: e.chain, privateKey: e.privateKey, contentDigest });
    expect(ours.toString('hex')).toBe(javaCms.toString('hex'));
  });
});
