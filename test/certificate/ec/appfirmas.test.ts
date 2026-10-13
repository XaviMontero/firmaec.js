import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as mod from '../../../src/certificate/ec/appfirmas/index.js';
import * as certs from '../../../src/certificate/ec/appfirmas/certs.js';
import { der } from '../../../src/asn1/der.js';
import { createCa, ext, ExtSpec, issue, NameSpec, TestCa } from '../../helpers/pki.js';
import { jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const P = '1.3.6.1.4.1.62431';
const issuerNames = ['APPFIRMAS S.A.', 'APPFIRMAS S.A. SUB CA', 'APPFIRMAS S.A.'.toLowerCase()].filter((o) => o !== '');
const cas: TestCa[] = issuerNames.map((o, i) => createCa([['C', 'EC'], ['O', o], ['CN', 'SUBCA TEST ' + i]], 'appfirmas-' + i));

const subj: NameSpec = [
  ['C', 'EC'],
  ['L', 'GUAYAQUIL'],
  ['O', 'EMPRESA, "LA MEJOR" S.A.'],
  ['OU', 'SISTEMAS'],
  ['T', 'GERENTE GENERAL'],
  ['2.5.4.97', 'VATEC-1790012345001', 'printable'],
  ['SERIALNUMBER', 'IDCEC-1712345678', 'printable'],
  ['GN', 'MARÍA JOSÉ'],
  ['SN', 'LÓPEZ ORDÓÑEZ'],
  ['CN', 'MARÍA JOSÉ LÓPEZ ORDÓÑEZ'],
];

const subjVariants: Record<string, NameSpec> = {
  full: subj,
  bmp: [['C', 'EC'], ['O', 'ÁRBOL, S.A.', 'bmp'], ['T', 'CARGO', 'bmp'], ['2.5.4.97', 'VATEC-0991234567001', 'bmp'], ['SERIALNUMBER', 'PASEC-A1234', 'bmp'], ['GN', 'ÑOÑO', 'bmp'], ['SN', 'PIÑA', 'bmp'], ['CN', 'SELLO ÑOÑO', 'bmp']],
  printableNoPrefix: [['C', 'EC'], ['O', 'EMPRESA SA', 'printable'], ['SERIALNUMBER', '1712345678', 'printable'], ['2.5.4.97', '1790012345001', 'printable'], ['CN', 'PRINTABLE CN', 'printable']],
  cnOnly: [['CN', 'SOLO CN']],
};

// fields in extensions / SAN are ignored by this CA, but present to check they are not read
const noise: ExtSpec[] = [
  ext.string(`${P}.3.1`, 'EXT-1712345678'),
  ext.san({ email: 'user@appfirmas.ec', otherNames: [{ oid: `${P}.3.1`, value: der.utf8('SAN-1712345678') }] }),
];

const policies = [...'2.1.1 2.2.1 2.3.1 102.2.4.1'.split(' ').map((p) => `${P}.${p}`), '1.2.3.4'];

function buildCerts(): Array<[string, Buffer]> {
  const out: Array<[string, Buffer]> = [];
  for (const p of policies) {
    for (const [name, s] of Object.entries(subjVariants)) {
      out.push([`${p} ${name}`, issue(cas[0], s, [ext.policies(p), ...noise]).cert]);
    }
    cas.slice(1).forEach((ca, i) => out.push([`${p} issuer ${i + 1}`, issue(ca, subj, [ext.policies(p)]).cert]));
  }
  out.push(['two policies (first branch wins)', issue(cas[0], subj, [ext.policies(`${P}.2.3.1`, `${P}.2.1.1`)]).cert]);
  out.push(['no policies', issue(cas[0], subj, noise).cert]);
  out.push(['no extensions', issue(cas[0], subj, [], { withKeyUsage: false }).cert]);
  return out;
}

describe('AppFirmas', () => {
  const built = buildCerts();

  it('getRootCertificate returns null for test leaf certificates', () => {
    for (const [, c] of built.slice(0, 10)) expect(mod.getRootCertificate(new Certificate(c))).toBeNull();
  });

  it('every embedded CA certificate parses', () => {
    for (const c of Object.values(certs)) expect((c as Certificate).subjectPrincipal).toMatch(/APPFIRMAS/i);
  });

  it.skipIf(!oracleAvailable)('extracts the same DatosUsuario as Java', () => {
    const expected = oracleDatos(built.map(([, c]) => c));
    built.forEach(([label, c], i) => expect(jsDatos(c), label).toEqual(expected[i]));
  });
});
