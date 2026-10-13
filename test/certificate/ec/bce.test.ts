import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as bce from '../../../src/certificate/ec/bce/index.js';
import * as certs from '../../../src/certificate/ec/bce/certs.js';
import { der } from '../../../src/asn1/der.js';
import { createCa, ext, ExtSpec, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const B = '1.3.6.1.4.1.37947';
const cas = [
  createCa([['C', 'EC'], ['O', 'BANCO CENTRAL DEL ECUADOR'], ['OU', 'ENTIDAD DE CERTIFICACION DE INFORMACION-ECIBCE'], ['CN', 'AC BCE TEST']], 'bce'),
  createCa([['C', 'EC'], ['O', 'Banco Central del Ecuador'], ['CN', 'AC BCE lower']], 'bce-lower'),
];

const fields: ExtSpec[] = [
  ext.string(`${B}.3.1`, 'IDCEC-1712345678'),
  ext.string(`${B}.3.2`, 'JUAN CARLOS'),
  ext.string(`${B}.3.3`, 'PÉREZ'),
  ext.string(`${B}.3.4`, 'ÑANDÚ "EL" , SEGUNDO', 'bmp'),
  ext.string(`${B}.3.5`, 'GERENTE, GENERAL'),
  ext.string(`${B}.3.6`, 'MINISTERIO DE ECONOMÍA'),
  ext.string(`${B}.3.7`, 'AV. AMAZONAS'),
  ext.string(`${B}.3.8`, '022222222', 'printable'),
  ext.string(`${B}.3.9`, 'QUITO'),
  ext.string(`${B}.3.10`, 'EMPRESA, S.A.'),
  ext.string(`${B}.3.11`, 'VATEC-1790012345001', 'printable'),
  ext.string(`${B}.3.12`, 'ECUADOR'),
];

const subj: NameSpec = [
  ['C', 'EC'],
  ['O', 'EMPRESA, "LA MEJOR" S.A.'],
  ['T', 'CONTADOR'],
  ['SERIALNUMBER', 'IDCEC-1712345678', 'printable'],
  ['GN', 'MARÍA JOSÉ'],
  ['SN', 'LÓPEZ'],
  ['CN', 'MARÍA JOSÉ LÓPEZ'],
];

const extSets: Record<string, ExtSpec[]> = {
  full: fields,
  cedulaOnly: [fields[0]],
  // OID ending in "3.1" from another arc: still matches the pattern
  patternOnly: [ext.string('1.3.6.1.4.1.99999.13.1', 'X')],
  // no OID ends with "3.1" -> construir returns null
  noPattern: fields.slice(1),
  none: [],
};

const policies = [`${B}.2.1.1`, `${B}.2.2.1`, `${B}.2.3.1`, `${B}.4.1`, '1.3.6.1.4.1.56105.2.1.1', '1.2.3.4'];

const san = ext.san({ email: 'user@bce.ec', otherNames: [{ oid: `${B}.3.1`, value: der.utf8('SAN') }] });

function buildCerts(): Array<[string, Buffer]> {
  const out: Array<[string, Buffer]> = [];
  for (const p of policies) {
    for (const [name, set] of Object.entries(extSets)) {
      out.push([`${p} ${name}`, issue(cas[0], subj, [ext.policies(p), ...set, san]).cert]);
    }
    out.push([`${p} lower issuer`, issue(cas[1], [['CN', 'SOLO CN']], [ext.policies(p), ...fields]).cert]);
  }
  out.push(['PN + FP (first wins)', issue(cas[0], subj, [ext.policies(`${B}.2.3.1`, `${B}.2.1.1`), ...fields]).cert]);
  out.push(['no policies', issue(cas[0], subj, fields).cert]);
  out.push(['no extensions', issue(cas[0], subj, [], { withKeyUsage: false }).cert]);
  return out;
}

describe('Banco Central del Ecuador', () => {
  const built = buildCerts();

  it('getRootCertificate returns null for test leaf certificates', () => {
    for (const [, c] of built.slice(0, 10)) expect(bce.getRootCertificate(new Certificate(c))).toBeNull();
  });

  it('every embedded CA certificate parses', () => {
    for (const c of Object.values(certs)) expect((c as Certificate).subjectPrincipal).toMatch(/BANCO CENTRAL/i);
  });

  it.skipIf(!oracleAvailable)('extracts the same DatosUsuario as Java', () => {
    const expected = oracleDatos(built.map(([, c]) => c));
    built.forEach(([label, c], i) => expect(jsDatos(c), label).toEqual(expected[i]));
  });
});
