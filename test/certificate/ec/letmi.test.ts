import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as mod from '../../../src/certificate/ec/letmi/index.js';
import * as certs from '../../../src/certificate/ec/letmi/certs.js';
import { createCa, ext, issue, NameSpec } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const P = '1.3.6.1.4.1.62566';
const ca = createCa([['C', 'EC'], ['O', 'LETMI ECUADOR S.A.'], ['CN', 'Letmi SUBCA TEST']], 'letmi');

const subj: NameSpec = [
  ['C', 'EC'],
  ['L', 'GUAYAQUIL'],
  ['O', 'EMPRESA, "Ñ" S.A.'],
  ['T', 'GERENTE GENERAL'],
  ['2.5.4.97', 'VATEC-1790012345001'],
  ['SERIALNUMBER', 'IDCEC-1712345678'],
  ['GN', 'MARÍA JOSÉ'],
  ['SN', 'LÓPEZ PÉREZ'],
  ['CN', 'MARÍA JOSÉ LÓPEZ'],
];
const subjBmp: NameSpec = [
  ['C', 'EC', 'printable'],
  ['O', 'SELLOS Ñ CIA. LTDA.', 'bmp'],
  ['2.5.4.97', '1790012345001', 'printable'],
  ['SERIALNUMBER', 'PASEC-AB123', 'printable'],
  ['GN', 'JOSÉ', 'bmp'],
  ['SN', 'ÁLVAREZ', 'bmp'],
  ['CN', 'SELLO, ELECTRÓNICO', 'bmp'],
];
// Persona natural sin RUC (no Organization Identifier)
const subjSinRuc: NameSpec = [['C', 'EC'], ['SERIALNUMBER', 'IDCEC-0912345678'], ['GN', 'ANA'], ['SN', 'TORRES'], ['CN', 'ANA TORRES']];

const policies = [
  ...['2.1.2', '2.1.1', '2.3.2', '2.3.1', '2.2.2', '2.2.1', '102.2.4.2', '102.2.4.1'].map((p) => `${P}.${p}`),
  '1.2.3.4', // unknown policy -> datos null
];

describe.skipIf(!oracleAvailable)('Letmi parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    const list: Buffer[] = [];
    policies.forEach((p, i) => {
      for (const s of [subj, subjBmp, subjSinRuc]) {
        list.push(issue(ca, s, [ext.policies(p), ext.san({ email: 'u' + i + '@x.ec' })]).cert);
      }
      // without subject attributes / SAN
      list.push(issue(ca, [['CN', 'SOLO CN']], [ext.policies(p)]).cert);
    });
    // precedence with several policies
    list.push(issue(ca, subj, [ext.policies(`${P}.102.2.4.1`, `${P}.2.3.2`, `${P}.2.2.1`)]).cert);
    list.push(issue(ca, subj, [ext.policies(`${P}.102.2.4.2`, `${P}.2.1.1`)]).cert);
    list.push(issue(ca, subj, [ext.policies(`${P}.2.3.1`, `${P}.2.2.2`)]).cert);
    // no extensions at all
    list.push(issue(ca, subj, []).cert);
    const expected = oracleDatos(list);
    list.forEach((c, i) => expect(jsDatos(c), `cert #${i}`).toEqual(expected[i]));
    const tiposVistos = new Set(expected.map((e) => (e.datos ? e.datos.tipoCertificado : e.datos === null ? 'null' : e.error)));
    expect([...tiposVistos].sort()).toEqual(
      ['null', 'Persona Natural', 'Miembro Empresa', 'Representante Legal', 'Sellado Electrónico'].sort(),
    );
    expect(new Set(expected.map((e) => e.entidad))).toEqual(new Set(['LETMI ECUADOR S.A.']));
  });
});

describe('Letmi root certificates', () => {
  it('returns null for leaf certs not signed by the real CA', () => {
    const leaf = issue(ca, subj, [ext.policies(policies[0])]).cert;
    expect(mod.getRootCertificate(new Certificate(leaf))).toBeNull();
  });
  it('parses every embedded CA certificate', () => {
    for (const [name, c] of Object.entries(certs)) {
      expect(c.subject.toString(), name).toBeTruthy();
    }
  });
});
