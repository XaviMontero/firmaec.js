import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as corpnewbest from '../../../src/certificate/ec/corpnewbest/index.js';
import * as certs from '../../../src/certificate/ec/corpnewbest/certs.js';
import { createCa, ext, ExtSpec, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const P = '1.3.6.1.4.1.34380';
const S = '1.3.6.1.4.1.64849';
// every issuer O variant mapped to CORPNEWBEST by getNombreCA (exact match after toUpperCase)
const cas = [
  createCa([['C', 'EC'], ['O', 'CORPNEWBEST CIA. LTDA.'], ['CN', 'SUBCA CNB']], 'cnb'),
  createCa([['C', 'EC'], ['O', 'CorpNewBest Cia. Ltda.', 'printable'], ['CN', 'SUBCA CNB 2']], 'cnb2'),
];

const extSets: Record<string, ExtSpec[]> = {
  full: [
    ext.string(`${P}.3.1`, 'IDCEC-1712345678'),
    ext.string(`${P}.3.2`, 'JUAN CARLOS'),
    ext.string(`${P}.3.3`, 'PÉREZ'),
    ext.string(`${P}.3.4`, 'ÑANDÚ', 'bmp'),
    ext.string(`${P}.3.5`, 'GERENTE, GENERAL'),
    ext.string(`${P}.3.6`, 'MINISTERIO'),
    ext.string(`${P}.3.7`, 'AV. SIEMPRE VIVA 123'),
    ext.string(`${P}.3.8`, '022222222', 'printable'),
    ext.string(`${P}.3.9`, 'QUITO'),
    ext.string(`${P}.3.10`, 'EMPRESA "LA ÚNICA" S.A.'),
    ext.string(`${P}.3.11`, 'VATEC-1790012345001', 'printable'),
    ext.string(`${P}.3.12`, 'ECUADOR', 'ia5'),
  ],
  onlyCedula: [ext.string(`${P}.3.1`, 'PASEC-AB12345', 'printable')],
  // other OID matching the "1.3.6.1.4.1" + "34380.3.1" pattern (not the real cedula OID)
  lookalike: [ext.string('1.3.6.1.4.1.134380.3.1', 'X'), ext.string(`${P}.3.2`, 'ANA', 't61')],
  none: [],
};

const subjects: Record<string, NameSpec> = {
  full: [
    ['C', 'EC'],
    ['L', 'GUAYAQUIL'],
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
    ['T', 'JEFE', 'printable'],
    ['2.5.4.97', '1790012345001', 'printable'],
    ['SERIALNUMBER', 'PASEC-A123'],
    ['GN', 'PEDRO', 'printable'],
    ['SN', 'GÓMEZ', 'bmp'],
    ['CN', 'SELLO ÑANDÚ', 'bmp'],
  ],
  cnOnly: [['CN', 'SOLO CN']],
};

const policies = [
  ...['2.7', '2.8', '2.10'].map((p) => `${P}.${p}`),
  ...['2.1.1', '2.1.2', '2.2.1', '2.2.2', '2.3.1', '2.3.2', '102.2.4.1', '102.2.4.2', '102.2.5.1'].map((p) => `${S}.${p}`),
  '1.2.3.4', // unknown policy -> datos null
];

function buildCerts(): { label: string; cert: Buffer }[] {
  const out: { label: string; cert: Buffer }[] = [];
  policies.forEach((p, i) => {
    for (const [en, es] of Object.entries(extSets)) {
      for (const [sn, s] of Object.entries(subjects)) {
        const ca = cas[(i + out.length) % cas.length];
        out.push({ label: `${p} ext=${en} subj=${sn}`, cert: issue(ca, s, [ext.policies(p), ...es, ext.san({ email: `u${i}@x.ec` })]).cert });
      }
    }
  });
  // two policies at once (first matching branch wins)
  out.push({ label: 'ext 2.10+2.7', cert: issue(cas[0], subjects.full, [ext.policies(`${P}.2.10`, `${P}.2.7`), ...extSets.full]).cert });
  out.push({ label: 'subj 102.2.5.1+2.3.1', cert: issue(cas[0], subjects.full, [ext.policies(`${S}.102.2.5.1`, `${S}.2.3.1`)]).cert });
  // no extensions at all / no policies
  out.push({ label: 'no extensions', cert: issue(cas[0], subjects.full, [], { withKeyUsage: false }).cert });
  out.push({ label: 'ext fields, no policies', cert: issue(cas[1], subjects.full, extSets.full).cert });
  return out;
}

describe.skipIf(!oracleAvailable)('CorpNewBest parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    const certs = buildCerts();
    const expected = oracleDatos(certs.map((c) => c.cert));
    certs.forEach((c, i) => expect(jsDatos(c.cert), c.label).toEqual(expected[i]));
    // sanity: the CA was recognized
    // every construir branch was exercised
    const tiposVistos = new Set(expected.map((e) => (e.datos ? e.datos.tipoCertificado : e.datos === null ? 'null' : e.error)));
    expect(tiposVistos).toEqual(new Set([
      'Persona Natural (EXT)',
      'Persona Jurídica (EXT)',
      'Miembro Empresa (EXT)',
      'Persona Natural',
      'Miembro Empresa',
      'Representante Legal',
      'Sello Electrónico',
      'Sellado de Tiempo',
      'null',
    ]));
    // every issuer variant was recognized as this CA
    expect(new Set(expected.map((e) => e.entidad))).toEqual(new Set(['CORPNEWBEST CIA. LTDA.']));
  });
});

describe('CorpNewBest root certificates', () => {
  it('returns null for leaves not signed by the real CorpNewBest sub CAs', () => {
    for (const c of buildCerts().slice(0, 6)) expect(corpnewbest.getRootCertificate(new Certificate(c.cert))).toBeNull();
  });

  it('every embedded certificate parses', () => {
    const all = Object.values(certs);
    expect(all.length).toBe(12);
    for (const c of all) {
      expect(c).toBeInstanceOf(Certificate);
      expect(c.subjectPrincipal).toMatch(/CN=/);
    }
  });
});
