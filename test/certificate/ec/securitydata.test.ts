import { describe, expect, it } from 'vitest';
import { createCa, ext, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const SD = '1.3.6.1.4.1.37746';
const ca = createCa([['C', 'EC'], ['O', 'SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A.'], ['CN', 'SUBCA TEST']], 'sd');
const caOld = createCa([['C', 'EC'], ['O', 'SECURITY DATA S.A. 2'], ['CN', 'SUBCA OLD']], 'sd-old');

const extFields = [
  ext.string(`${SD}.3.1`, '1712345678'),
  ext.string(`${SD}.3.2`, 'JUAN CARLOS'),
  ext.string(`${SD}.3.3`, 'PÉREZ'),
  ext.string(`${SD}.3.4`, 'ÑANDÚ'),
  ext.string(`${SD}.3.5`, 'GERENTE, GENERAL'),
  ext.string(`${SD}.3.6`, 'MINISTERIO'),
  ext.string(`${SD}.3.10`, 'EMPRESA S.A.'),
  ext.string(`${SD}.3.11`, '1790012345001', 'printable'),
];

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
  ...['2.7', '2.8', '2.9', '2.10', '2.11', '2.15', '3.28'].map((p) => `${SD}.${p}`),
  ...['2.1.1', '2.1.2', '2.2.1', '2.2.2', '2.3.1', '2.3.2', '102.2.4.1', '102.2.4.2', '102.2.5.1'].map((p) => `${SD}.${p}`),
  '1.2.3.4', // unknown policy -> datos null
];

describe.skipIf(!oracleAvailable)('Security Data parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    const certs: Buffer[] = [];
    policies.forEach((p, i) => {
      for (const issuer of [ca, caOld]) {
        certs.push(issue(issuer, subj, [ext.policies(p), ...extFields, ext.san({ email: 'u' + i + '@x.ec' })]).cert);
      }
      // without extensions / subject attributes
      certs.push(issue(ca, [['CN', 'SOLO CN']], [ext.policies(p)]).cert);
    });
    const expected = oracleDatos(certs);
    certs.forEach((c, i) => expect(jsDatos(c), `cert #${i}`).toEqual(expected[i]));
  });
});
