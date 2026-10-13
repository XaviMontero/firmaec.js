import { describe, expect, it } from 'vitest';
import { der } from '../../../src/asn1/der.js';
import { Certificate } from '../../../src/x509/certificate.js';
import * as eclipsoft from '../../../src/certificate/ec/eclipsoft/index.js';
import { createCa, encodeString, ext, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const E = '1.3.6.1.4.1.57153';
const cas = [
  createCa([['C', 'EC'], ['O', 'ECLIPSOFT S.A.'], ['CN', 'ECLIPSOFT SUBCA']], 'ecl'),
  createCa([['C', 'ES'], ['O', 'UANATACA S.A.'], ['CN', 'UANATACA CA1 2016']], 'ecl-uan'),
  createCa([['C', 'ES'], ['O', 'UANATACA S.A.'], ['CN', 'uanataca ca1 2016']], 'ecl-uan-lower'),
];

const sanFull = (i: number) =>
  ext.san({
    email: `u${i}@x.ec`,
    otherNames: [
      { oid: `${E}.102.3.1`, value: der.utf8('PASEC-AB123456') },
      { oid: `${E}.102.3.2`, value: der.utf8('JOSÉ "PEPE" LUIS') },
      { oid: `${E}.102.3.3`, value: der.utf8('PÉREZ, Jr.') },
      { oid: `${E}.102.3.4`, value: encodeString('ÑANDÚ', 'bmp') },
      { oid: `${E}.102.3.5`, value: der.utf8('GERENTE, GENERAL') },
      { oid: `${E}.102.3.10`, value: der.utf8('EMPRESA Ñ S.A.') },
      { oid: `${E}.102.3.11`, value: der.printable('VATEC-1790012345001') },
    ],
  });
const sanPartial = ext.san({ otherNames: [{ oid: `${E}.102.3.2`, value: der.ia5('ANA') }, { oid: `${E}.102.3.11`, value: der.utf8('1790012345001') }] });

const subj: NameSpec = [
  ['C', 'EC'],
  ['O', 'EMPRESA, S.A.'],
  ['T', 'CONTADOR'],
  ['2.5.4.97', 'VATEC-1790012345001'],
  ['SERIALNUMBER', 'IDCEC-1712345678'],
  ['GN', 'MARÍA JOSÉ'],
  ['SN', 'LÓPEZ'],
  ['CN', 'MARÍA JOSÉ LÓPEZ'],
];

const policies = [
  ...['1.1.1', '1.2', '2.1', '2.2', '3.1', '3.2', '4.1', '4.2', '5.2'].map((p) => `${E}.1.1.${p}`),
  `${E}.1.1.5.1`, // matches the prefix but not a known type -> null
  `${E}.1.1`, // the prefix itself -> null
  `${E}.1.10.1.1`, // startsWith "…57153.1.1" (string prefix quirk) -> null
  `${E}.2.1.1`, // subject-based OIDs are commented out in Java -> null
  '1.2.3.4',
];

describe.skipIf(!oracleAvailable)('Eclipsoft parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    const list: Buffer[] = [];
    policies.forEach((p, i) => {
      for (const ca of cas) {
        list.push(issue(ca, subj, [ext.policies(p), sanFull(i)]).cert);
      }
      list.push(issue(cas[0], subj, [ext.policies(p), sanPartial]).cert);
      list.push(issue(cas[0], [['CN', 'SOLO CN']], [ext.policies(p)]).cert);
    });
    // precedence with several policies
    list.push(issue(cas[0], subj, [ext.policies(`${E}.1.1.5.2`, `${E}.1.1.4.1`, `${E}.1.1.2.2`), sanFull(99)]).cert);
    list.push(issue(cas[1], subj, [ext.policies('1.2.3.4', `${E}.1.1.3.2`), sanFull(98)]).cert);
    // no extensions at all
    list.push(issue(cas[0], subj, []).cert);
    const expected = oracleDatos(list);
    list.forEach((c, i) => expect(jsDatos(c), `cert #${i}`).toEqual(expected[i]));
    const tiposVistos = new Set(expected.map((e) => (e.datos ? e.datos.tipoCertificado : e.datos === null ? 'null' : e.error)));
    expect([...tiposVistos].sort()).toEqual(
      [
        'null',
        'Persona Natural (EXT)',
        'Miembro Empresa (EXT)',
        'Representante Legal (EXT)',
        'Persona Jurídica Privada (EXT)',
        'Sellado de Tiempo (EXT)',
      ].sort(),
    );
    expect(new Set(expected.map((e) => e.entidad))).toEqual(new Set(['ECLIPSOFT S.A.']));
  });
});

describe('Eclipsoft root certificates', () => {
  it('returns null for leaf certs not signed by the real (Uanataca) CAs', () => {
    const leaf = issue(cas[1], subj, [ext.policies(`${E}.1.1.1.1`)]).cert;
    expect(eclipsoft.getRootCertificate(new Certificate(leaf))).toBeNull();
  });
});
