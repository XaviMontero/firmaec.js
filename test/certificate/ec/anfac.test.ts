import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as anfac from '../../../src/certificate/ec/anfac/index.js';
import * as certs from '../../../src/certificate/ec/anfac/certs.js';
import { der } from '../../../src/asn1/der.js';
import { createCa, ext, ExtSpec, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const A = '1.3.6.1.4.1.18332';
const B = '1.3.6.1.4.1.37442';
const cas = [
  createCa([['C', 'EC'], ['O', 'ANFAC AUTORIDAD DE CERTIFICACION ECUADOR C.A.'], ['CN', 'ANFAC SUBCA TEST']], 'anfac'),
  createCa([['C', 'EC'], ['O', 'ANFAC AUTORIDAD DE CERTIFICACION ECUADOR CA'], ['CN', 'ANFAC OLD']], 'anfac-old'),
  // getNombreCA compares the upper-cased O
  createCa([['C', 'EC'], ['O', 'anfac autoridad de certificacion ecuador c.a.'], ['CN', 'anfac lower']], 'anfac-lower'),
];

const fields = (base: string): ExtSpec[] => [
  ext.string(`${base}.3.1`, 'IDCEC-1712345678'),
  ext.string(`${base}.3.2`, 'JUAN CARLOS'),
  ext.string(`${base}.3.3`, 'PÉREZ'),
  ext.string(`${base}.3.4`, 'ÑANDÚ "EL" , SEGUNDO', 'bmp'),
  ext.string(`${base}.3.5`, 'GERENTE, GENERAL'),
  ext.string(`${base}.3.6`, 'MINISTERIO DE ECONOMÍA'),
  ext.string(`${base}.3.7`, 'AV. AMAZONAS'),
  ext.string(`${base}.3.8`, '022222222', 'printable'),
  ext.string(`${base}.3.9`, 'QUITO'),
  ext.string(`${base}.3.10`, base === A ? 'EMPRESA 18332 S.A.' : 'EMPRESA 37442 S.A.'),
  ext.string(`${base}.3.11`, 'VATEC-1790012345001', 'printable'),
  ext.string(`${base}.3.12`, 'ECUADOR'),
];

const subj: NameSpec = [
  ['C', 'EC'],
  ['L', 'QUITO'],
  ['O', 'EMPRESA, "LA MEJOR" S.A.'],
  ['T', 'CONTADOR'],
  ['2.5.4.97', 'VATEC-1790012345001', 'printable'],
  ['SERIALNUMBER', 'IDCEC-1712345678', 'printable'],
  ['GN', 'MARÍA JOSÉ'],
  ['SN', 'LÓPEZ ORDÓÑEZ', 'bmp'],
  ['CN', 'MARÍA JOSÉ LÓPEZ'],
];

const extSets: Record<string, ExtSpec[]> = {
  ext18332: fields(A),
  ext37442: fields(B),
  both: [...fields(A), ...fields(B)],
  // only a field whose OID ends with "3.1" (pattern match), no data
  patternOnly: [ext.string('1.3.6.1.4.1.99999.13.1', 'X')],
  // "3.11" does not end with "3.1": goes to the subject branch
  rucOnly: [ext.string(`${B}.3.11`, '1790012345001')],
  none: [],
};

const policies = [
  `${A}.3.4.1.2.22`, `${A}.2.5.1.3`, `${A}.4.1.3.22`,
  `${B}.3.4.1.2.22`, `${B}.3.4.1.4.22`, `${B}.2.5.1.3`, `${B}.2.5.1.10`, `${B}.4.1.3.22`, `${B}.102.2.5.1`,
  `${B}.2.1.1`, `${B}.2.2.1`, `${B}.2.3.1`, `${B}.102.2.4.1`,
  '1.2.3.4',
];

const san = ext.san({ email: 'user@anfac.ec', otherNames: [{ oid: `${B}.3.1`, value: der.utf8('SAN-1712345678') }] });

function buildCerts(): Array<[string, Buffer]> {
  const out: Array<[string, Buffer]> = [];
  for (const p of policies) {
    for (const [name, set] of Object.entries(extSets)) {
      out.push([`${p} ${name}`, issue(cas[0], subj, [ext.policies(p), ...set, san]).cert]);
    }
    out.push([`${p} old issuer`, issue(cas[1], subj, [ext.policies(p), ...fields(B)]).cert]);
    out.push([`${p} lower issuer`, issue(cas[2], subj, [ext.policies(p)]).cert]);
    out.push([`${p} bare subject`, issue(cas[0], [['CN', 'SOLO CN']], [ext.policies(p)]).cert]);
    out.push([`${p} bare subject ext`, issue(cas[0], [['CN', 'SOLO CN']], [ext.policies(p), ...fields(B)]).cert]);
  }
  // 18332 type + 37442 type: construir37442 overwrites the result
  out.push(['18332 PN + 37442 PJ', issue(cas[0], subj, [ext.policies(`${A}.3.4.1.2.22`, `${B}.2.5.1.3`), ...fields(A), ...fields(B)]).cert]);
  out.push(['18332 PJ + 37442 FP', issue(cas[0], subj, [ext.policies(`${A}.2.5.1.3`, `${B}.4.1.3.22`), ...fields(A)]).cert]);
  out.push(['18332 FP + subj PN', issue(cas[0], subj, [ext.policies(`${A}.4.1.3.22`, `${B}.2.1.1`), ...fields(A)]).cert]);
  out.push(['subj PN + ME (first wins)', issue(cas[0], subj, [ext.policies(`${B}.2.2.1`, `${B}.2.1.1`)]).cert]);
  out.push(['no policies', issue(cas[0], subj, [...fields(B)]).cert]);
  out.push(['no extensions', issue(cas[0], subj, [], { withKeyUsage: false }).cert]);
  return out;
}

describe('ANFAC', () => {
  const built = buildCerts();

  it('getRootCertificate returns null for test leaf certificates', () => {
    for (const [, c] of built.slice(0, 20)) expect(anfac.getRootCertificate(new Certificate(c))).toBeNull();
  });

  it('every embedded CA certificate parses', () => {
    for (const c of Object.values(certs)) expect((c as Certificate).subjectPrincipal).toMatch(/ANF/i);
  });

  it.skipIf(!oracleAvailable)('extracts the same DatosUsuario as Java', () => {
    const expected = oracleDatos(built.map(([, c]) => c));
    built.forEach(([label, c], i) => expect(jsDatos(c), label).toEqual(expected[i]));
  });
});
