import { describe, expect, it } from 'vitest';
import { der } from '../../../src/asn1/der.js';
import { Certificate } from '../../../src/x509/certificate.js';
import * as uanataca from '../../../src/certificate/ec/uanataca/index.js';
import * as certs from '../../../src/certificate/ec/uanataca/certs.js';
import { createCa, encodeString, ext, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const EXT = '1.3.6.1.4.1.47286.102';
const SUBJ = '1.3.6.1.4.1.65311';
const cas = [
  createCa([['C', 'EC'], ['O', 'UANATACA ECUADOR S.A.'], ['CN', 'UANATACA CA2 2021']], 'uan'),
  createCa([['C', 'ES'], ['O', 'UANATACA S.A.'], ['CN', 'UANATACA CA2 2016']], 'uan-old'),
  createCa([['C', 'ES'], ['O', 'GRUPO UANATACA S.A. TEST'], ['CN', 'OTRA CA']], 'uan-old2'),
];

const sanFull = (i: number) =>
  ext.san({
    email: `u${i}@x.ec`,
    otherNames: [
      { oid: `${EXT}.3.1`, value: der.utf8('1712345678') },
      { oid: `${EXT}.3.2`, value: der.utf8('JOSÉ "PEPE" LUIS') },
      { oid: `${EXT}.3.3`, value: der.utf8('PÉREZ, Jr.') },
      { oid: `${EXT}.3.4`, value: encodeString('ÑANDÚ', 'bmp') },
      { oid: `${EXT}.3.5`, value: der.utf8('GERENTE, GENERAL') },
      { oid: `${EXT}.3.10`, value: der.utf8('EMPRESA Ñ S.A.') },
      { oid: `${EXT}.3.11`, value: der.printable('1790012345001') },
    ],
  });
// SAN with only some otherNames (missing apellido 2, cargo, razon social)
const sanPartial = ext.san({ otherNames: [{ oid: `${EXT}.3.2`, value: der.ia5('ANA') }, { oid: `${EXT}.3.3`, value: der.utf8('LOPEZ') }] });

const subj: NameSpec = [
  ['C', 'EC'],
  ['L', 'QUITO'],
  ['O', 'EMPRESA, S.A.'],
  ['T', 'CONTADOR "SENIOR"'],
  ['2.5.4.97', 'VATEC-1790012345001'],
  ['SERIALNUMBER', 'IDCEC-1712345678'],
  ['GN', 'MARÍA JOSÉ', 'bmp'],
  ['SN', 'LÓPEZ'],
  ['CN', 'MARÍA JOSÉ LÓPEZ'],
];
const subjPrintable: NameSpec = [['C', 'EC'], ['SERIALNUMBER', 'PASEC-AB123', 'printable'], ['CN', 'SELLO TSA', 'printable']];

const policies = [
  ...['2.1.1', '2.1.2', '2.4.1', '2.4.2', '2.2.1', '2.2.2', '2.3.1', '2.3.2', '2.5.1'].map((p) => `${EXT}.${p}`),
  ...['2.1.1', '2.1.2', '102.2.4.1', '102.2.4.2', '2.2.1', '2.2.2', '2.3.1', '2.3.2', '102.2.5.1'].map((p) => `${SUBJ}.${p}`),
  '1.2.3.4', // unknown policy -> datos null
];

describe.skipIf(!oracleAvailable)('Uanataca parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    const list: Buffer[] = [];
    policies.forEach((p, i) => {
      for (const ca of cas) {
        list.push(issue(ca, subj, [ext.policies(p), sanFull(i)]).cert);
      }
      list.push(issue(cas[0], subjPrintable, [ext.policies(p), sanPartial]).cert);
      // without SAN / subject attributes
      list.push(issue(cas[0], [['CN', 'SOLO CN']], [ext.policies(p)]).cert);
    });
    // precedence: several policies at once (EXT first, then SUBJ order)
    list.push(issue(cas[0], subj, [ext.policies(`${SUBJ}.2.1.1`, `${EXT}.2.5.1`), sanFull(99)]).cert);
    list.push(issue(cas[0], subj, [ext.policies(`${SUBJ}.102.2.5.1`, `${SUBJ}.2.3.2`, `${SUBJ}.2.2.1`), sanFull(98)]).cert);
    list.push(issue(cas[1], subj, [ext.policies(`${EXT}.2.3.1`, `${EXT}.2.2.1`, `${EXT}.2.4.1`), sanFull(97)]).cert);
    // no extensions at all
    list.push(issue(cas[0], subj, []).cert);
    const expected = oracleDatos(list);
    list.forEach((c, i) => expect(jsDatos(c), `cert #${i}`).toEqual(expected[i]));
    // sanity: every branch was reached on the Java side
    const tiposVistos = new Set(expected.map((e) => (e.datos ? e.datos.tipoCertificado : e.datos === null ? 'null' : e.error)));
    expect([...tiposVistos].sort()).toEqual(
      [
        'null',
        'Persona Natural (EXT)',
        'Miembro Empresa (EXT)',
        'Persona Jurídica Privada (EXT)',
        'Representante Legal (EXT)',
        'Sellado de Tiempo (EXT)',
        'Persona Natural',
        'Persona Jurídica',
        'Miembro Empresa',
        'Representante Legal',
        'Sellado de Tiempo',
      ].sort(),
    );
    expect(new Set(expected.map((e) => e.entidad))).toEqual(new Set(['UANATACA ECUADOR S.A.', 'UANATACA S.A.']));
  });
});

describe('Uanataca root certificates', () => {
  it('returns null for leaf certs not signed by the real CAs', () => {
    const leaf = issue(cas[0], subj, [ext.policies(`${EXT}.2.1.1`)]).cert;
    expect(uanataca.getRootCertificate(new Certificate(leaf))).toBeNull();
  });
  it('parses every embedded CA certificate', () => {
    for (const [name, c] of Object.entries(certs)) {
      expect(c.subject.toString(), name).toBeTruthy();
    }
  });
});
