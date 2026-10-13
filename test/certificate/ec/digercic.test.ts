import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as digercic from '../../../src/certificate/ec/digercic/index.js';
import * as certs from '../../../src/certificate/ec/digercic/certs.js';
import { EntidadCertificadoraNoValidaException } from '../../../src/errors.js';
import { createCa, ext, ExtSpec, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const D = '1.3.6.1.4.1.55519.1.1.1.5';
const DATIL = '1.3.6.1.4.1.52643';
// issuer O variants mapped to DIGERCIC by getNombreCA (exact match after toUpperCase; the comma forces quoting)
const cas = [
  createCa([['C', 'EC'], ['O', 'DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN Y CEDULACIÓN'], ['CN', 'SUBCA DIGERCIC']], 'dig'),
  createCa([['C', 'EC'], ['O', 'Dirección General de Registro Civil, Identificación y Cedulación', 'bmp'], ['CN', 'SUBCA DIGERCIC 2']], 'dig2'),
];

/*
 * Java CertEcUtils.getDatosUsuarios dispatches DIGERCIC certificates to
 * CertificadoDataFactoryDatil (bug kept), so the parity matrix mixes DIGERCIC's
 * own OIDs with Datil's.
 */
const extSets: Record<string, ExtSpec[]> = {
  // real DIGERCIC layout: nothing ends in "3.1" -> Datil's RESOLUCION-ARCOTEL branch
  digercic: [
    ext.string(`${D}.2.1`, 'IDCEC-1712345678'),
    ext.string(`${D}.2.2`, 'PASEC-AB123'),
    ext.string(`${D}.2.3`, 'PÉREZ ÑANDÚ'),
    ext.string(`${D}.2.4`, 'VATEC-1712345678001', 'printable'),
  ],
  // DIGERCIC OID ending in 3.1 -> Datil's EXT branch
  digercic31: [ext.string(`${D}.3.1`, 'X'), ext.string(`${D}.2.1`, '1712345678')],
  datil: [
    ext.string(`${DATIL}.3.1`, 'IDCEC-1712345678'),
    ext.string(`${DATIL}.3.2`, 'JUAN, CARLOS'),
    ext.string(`${DATIL}.3.3`, 'PÉREZ', 'bmp'),
    ext.string(`${DATIL}.3.4`, '"ÑANDÚ"'),
    ext.string(`${DATIL}.3.5`, 'GERENTE'),
    ext.string(`${DATIL}.3.10`, 'EMPRESA S.A.', 'printable'),
    ext.string(`${DATIL}.3.11`, 'VATEC-1790012345001', 'printable'),
  ],
  none: [],
};

const subjects: Record<string, NameSpec> = {
  full: [
    ['C', 'EC'],
    ['O', 'EMPRESA, "COMILLAS" S.A.'],
    ['T', 'CONTADOR'],
    ['2.5.4.97', 'VATEC-1790012345001'],
    ['SERIALNUMBER', 'IDCEC-1712345678'],
    ['GN', 'MARÍA JOSÉ'],
    ['SN', 'LÓPEZ'],
    ['CN', 'MARÍA JOSÉ LÓPEZ'],
  ],
  bmp: [
    ['C', 'EC'],
    ['O', 'ÑANDÚ CÍA', 'bmp'],
    ['SERIALNUMBER', 'PASEC-A123'],
    ['GN', 'PEDRO', 'printable'],
    ['SN', 'GÓMEZ', 'bmp'],
    ['CN', 'SELLO ÑANDÚ', 'bmp'],
  ],
  cnOnly: [['CN', 'SOLO CN']],
};

const policies = [
  `${D}.3.2`, // DIGERCIC persona natural
  `${D}.3.4`, // DIGERCIC sellado de tiempo
  ...['2.5.1', '2.5.2', '2.1.1', '2.2.1', '2.3.1', '102.2.4.1', '102.2.5.1'].map((p) => `${DATIL}.${p}`),
  '1.2.3.4',
];

function buildCerts(): { label: string; cert: Buffer }[] {
  const out: { label: string; cert: Buffer }[] = [];
  policies.forEach((p, i) => {
    for (const [en, es] of Object.entries(extSets)) {
      for (const [sn, s] of Object.entries(subjects)) {
        const ca = cas[(i + out.length) % cas.length];
        const extensions = [ext.policies(p), ...es, ext.san({ email: `u${i}@x.ec` })];
        out.push({ label: `${p} ext=${en} subj=${sn}`, cert: issue(ca, s, extensions).cert });
      }
    }
  });
  out.push({ label: 'no extensions', cert: issue(cas[0], subjects.full, [], { withKeyUsage: false }).cert });
  out.push({ label: 'ext fields, no policies', cert: issue(cas[1], subjects.full, extSets.datil).cert });
  return out;
}

describe.skipIf(!oracleAvailable)('DIGERCIC parity with Java (user data through Datil factory)', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    const certs = buildCerts();
    const expected = oracleDatos(certs.map((c) => c.cert));
    certs.forEach((c, i) => expect(jsDatos(c.cert), c.label).toEqual(expected[i]));
    const tiposVistos = new Set(expected.map((e) => (e.datos ? e.datos.tipoCertificado : e.datos === null ? 'null' : e.error)));
    expect(tiposVistos).toEqual(
      new Set([
        'Persona Natural (EXT)',
        'Persona Jurídica (EXT)',
        'Persona Natural',
        'Miembro Empresa',
        'Representante Legal',
        'Sellado Electrónico',
        'Sellado de Tiempo',
        'null',
      ]),
    );
    expect(new Set(expected.map((e) => e.entidad))).toEqual(
      new Set(['DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN Y CEDULACIÓN']),
    );
  });
});

/*
 * DIGERCIC's own factory (CertificadoDataFactoryDigercic.getDatosUsuarioDatil) is
 * unreachable from the Java dispatcher, so the oracle cannot run it: the expected
 * values below are derived by reading the Java code.
 */
describe('DIGERCIC own factory', () => {
  const leaf = (subject: NameSpec, extensions: ExtSpec[]) => new Certificate(issue(cas[0], subject, extensions).cert);

  it('Persona Natural (EXT): cedula from the DIGERCIC extension, nombre = CN, apellido empty', () => {
    const c = leaf(subjects.full, [ext.policies(`${D}.3.2`), ...extSets.digercic31, ...extSets.digercic]);
    expect(digercic.getDatosUsuario(c)?.toJSON()).toEqual({
      tipoCertificado: 'Persona Natural (EXT)',
      cedula: '1712345678',
      nombre: 'MARÍA JOSÉ LÓPEZ',
      apellido: '',
      ruc: '',
      razonSocial: '',
      institucion: '',
      cargo: '',
      commonName: '',
      email: '',
      certificadoDigitalValido: true,
    });
  });

  it('nombre falls back like Utils.getCN (OU, then the first RDN of the principal string)', () => {
    const ou = leaf([['C', 'EC'], ['OU', 'UNIDAD, CIVIL']], [ext.policies(`${D}.3.2`), ...extSets.digercic31]);
    expect(digercic.getDatosUsuario(ou)?.nombre).toBe('UNIDAD, CIVIL');
    const first = leaf([['C', 'EC'], ['O', 'ORG']], [ext.policies(`${D}.3.2`), ...extSets.digercic31]);
    expect(digercic.getDatosUsuario(first)?.nombre).toBe('ORG'); // principal string is in reverse RDN order
    const noCedula = leaf(subjects.cnOnly, [ext.policies(`${D}.3.2`), ext.string('1.3.6.1.4.1.9.3.1', 'X')]);
    expect(digercic.getDatosUsuario(noCedula)?.cedula).toBe('');
  });

  it('throws when a 3.1 extension is present but the policy is not persona natural', () => {
    for (const p of [`${D}.3.4`, '1.2.3.4']) {
      const c = leaf(subjects.full, [ext.policies(p), ...extSets.digercic31]);
      expect(() => digercic.getDatosUsuario(c)).toThrow(EntidadCertificadoraNoValidaException);
      expect(() => digercic.getDatosUsuario(c)).toThrow(
        'Certificado de DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN sin categorizar!',
      );
    }
  });

  it('returns null without an extension ending in 3.1 (real DIGERCIC layout)', () => {
    expect(digercic.getDatosUsuario(leaf(subjects.full, [ext.policies(`${D}.3.2`), ...extSets.digercic]))).toBeNull();
    expect(digercic.getDatosUsuario(new Certificate(issue(cas[0], subjects.full, [], { withKeyUsage: false }).cert))).toBeNull();
  });
});

describe('DIGERCIC root certificates', () => {
  it('returns null for leaves not signed by the real DIGERCIC sub CA', () => {
    for (const c of buildCerts().slice(0, 6)) expect(digercic.getRootCertificate(new Certificate(c.cert))).toBeNull();
  });

  it('every embedded certificate parses', () => {
    const all = Object.values(certs);
    expect(all.length).toBe(2);
    for (const c of all) {
      expect(c).toBeInstanceOf(Certificate);
      expect(c.subjectPrincipal).toMatch(/CN=/);
    }
  });
});
