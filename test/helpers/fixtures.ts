/** Shared e2e fixtures: signers (.p12 on disk) and sample PDFs / XMLs. */
import fs from 'node:fs';
import path from 'node:path';
import { PDFDocument, StandardFonts, degrees } from 'pdf-lib';
import { createCa, ext, issue, NameSpec, TestSigner, toP12, toPem } from './pki.js';
import { tmpDir } from './oracle.js';

export const PASSWORD = '123456';
const SD = '1.3.6.1.4.1.37746';

export const dir = tmpDir('firmaec-e2e-');

export interface SignerFixture {
  label: string;
  signer: TestSigner;
  p12: Buffer;
  p12Path: string;
  caPem: string;
}

function save(label: string, signer: TestSigner, caCert: Buffer, legacy = false): SignerFixture {
  const p12 = toP12(signer, PASSWORD, { legacy });
  const p12Path = path.join(dir, label + '.p12');
  fs.writeFileSync(p12Path, p12);
  const caPem = path.join(dir, label + '-ca.pem');
  fs.writeFileSync(caPem, toPem(caCert));
  return { label, signer, p12, p12Path, caPem };
}

const sdCa = createCa(
  [['C', 'EC'], ['O', 'SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A.'], ['OU', 'ENTIDAD DE CERTIFICACION DE INFORMACION'], ['CN', 'AUTORIDAD DE CERTIFICACION SUBCA-2 SECURITY DATA']],
  'sd-ca',
);
const sdCaEc = createCa([['C', 'EC'], ['O', 'SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A.'], ['CN', 'SUBCA EC']], 'sd-ca-ec', 'ec');

function sdNaturalExt(nombres: string, ap1: string, ap2: string, cedula = '1712345678') {
  return [
    ext.policies(`${SD}.2.7`),
    ext.string(`${SD}.3.1`, cedula),
    ext.string(`${SD}.3.2`, nombres),
    ext.string(`${SD}.3.3`, ap1),
    ext.string(`${SD}.3.4`, ap2),
    ext.san({ email: 'firmante@example.ec' }),
  ];
}

const subjectNatural: NameSpec = [
  ['C', 'EC'],
  ['O', 'SECURITY DATA S.A. 2'],
  ['OU', 'ENTIDAD DE CERTIFICACION DE INFORMACION'],
  ['SERIALNUMBER', '120326180125'],
  ['CN', 'JOSÉ MARÍA PÉREZ ÑANDÚ'],
];

export const signers = {
  /** Security Data, persona natural (extensions), RSA, AES p12. */
  natural: save('natural', issue(sdCa, subjectNatural, sdNaturalExt('JOSÉ MARÍA', 'PÉREZ', 'ÑANDÚ'), { label: 'natural' }), sdCa.cert),
  /** Same certificate packed as legacy (3DES/RC2) p12. */
  legacy: save('legacy', issue(sdCa, subjectNatural, sdNaturalExt('JOSÉ MARÍA', 'PÉREZ', 'ÑANDÚ'), { label: 'natural' }), sdCa.cert, true),
  /** Very long name (QR truncation at 57 chars, wrapping). */
  longName: save(
    'longname',
    issue(sdCa, [['C', 'EC'], ['CN', 'LONG']], sdNaturalExt('MARÍA DE LOS ÁNGELES GUADALUPE ALEJANDRA', 'VILLAVICENCIO-SANTISTEVAN', 'DE LA CUADRA ECHEVERRÍA'), { label: 'long' }),
    sdCa.cert,
  ),
  /** Sello electrónico (no cédula -> razón social is shown). */
  sello: save(
    'sello',
    issue(sdCa, [['C', 'EC'], ['O', 'EMPRESA ELÉCTRICA "LA LUZ", S.A.'], ['2.5.4.97', 'VATEC-1790012345001'], ['CN', 'SELLO EMPRESA']], [ext.policies(`${SD}.102.2.4.1`)], { label: 'sello' }),
    sdCa.cert,
  ),
  /** EC P-256 key. */
  ec: save('ec', issue(sdCaEc, subjectNatural, sdNaturalExt('ANA', 'TORRES', 'VEGA'), { label: 'ec', type: 'ec' }), sdCaEc.cert),
  /** Certificate from a CA the library does not know. */
  unknown: (() => {
    const ca = createCa([['C', 'US'], ['O', 'ACME TRUST'], ['CN', 'ACME CA']], 'acme');
    return save('unknown', issue(ca, [['C', 'US'], ['CN', 'John Doe']], [], { label: 'acme-leaf' }), ca.cert);
  })(),
};

// ------------------------------------------------------------------ documents

async function basePdf(opts: { pages?: number; rotate?: number } = {}): Promise<PDFDocument> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 1; i <= (opts.pages ?? 2); i++) {
    const p = doc.addPage([595, 842]);
    p.drawText(`Documento de prueba FirmaEC - página ${i}`, { x: 50, y: 780, size: 16, font });
    if (opts.rotate) p.setRotation(degrees(opts.rotate));
  }
  return doc;
}

export interface DocFixture {
  label: string;
  bytes: Buffer;
  path: string;
}

async function saveDoc(label: string, bytes: Uint8Array): Promise<DocFixture> {
  const p = path.join(dir, label + '.pdf');
  fs.writeFileSync(p, bytes);
  return { label, bytes: Buffer.from(bytes), path: p };
}

export async function pdfDocs(): Promise<DocFixture[]> {
  const simple = await basePdf();
  const objstm = await basePdf({ pages: 3 });
  const form = await basePdf();
  const f = form.getForm();
  f.createTextField('nombre').addToPage(form.getPage(0), { x: 50, y: 600, width: 200, height: 20 });
  f.getTextField('nombre').setText('Texto existente');
  return [
    await saveDoc('simple', await simple.save({ useObjectStreams: false })),
    await saveDoc('objstm', await objstm.save({ useObjectStreams: true })),
    await saveDoc('acroform', await form.save({ useObjectStreams: false })),
  ];
}

export function writeProps(label: string, props: Record<string, string | number>): string {
  const p = path.isAbsolute(label) ? label + '.properties' : path.join(dir, label + '.properties');
  // java.util.Properties.load(Reader) with UTF-8 reader (see Oracle.java)
  fs.writeFileSync(p, Object.entries(props).map(([k, v]) => `${k}=${String(v)}`).join('\n') + '\n', 'utf8');
  return p;
}

export function tmpFile(name: string): string {
  return path.join(dir, name);
}
