import { describe, expect, it } from 'vitest';
import { createCa, ext, issue, NameSpec } from '../helpers/pki.js';
import { jsX500, oracleAvailable, oracleX500 } from '../helpers/oracle.js';

const NAMES: NameSpec[] = [
  [['C', 'EC'], ['O', 'SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A.'], ['CN', 'JUAN PÉREZ']],
  [['C', 'EC'], ['O', 'DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN Y CEDULACIÓN'], ['CN', 'Ñandú "el" grande']],
  [['O', '  espacios  dobles  '], ['CN', 'trail ']],
  [['O', 'UANATACA S.A.'], ['CN', 'UANATACA CA1 2016']],
  [['O', 'bmp ÁÉÍ', 'bmp'], ['CN', 'print', 'printable'], ['2.5.4.97', 'VATEC-1790012345001']],
  [['O', 't61 ñ', 't61'], [['CN', 'multi'], ['SERIALNUMBER', '0102030405']], ['E', 'a@b.ec']],
  [['O', 'a+b=c<d>e;f#g\\h'], ['1.3.6.1.4.1.99.1', 'custom'], ['GN', 'Juan'], ['SN', 'Pérez'], ['T', 'Gerente']],
  [['O', '#hash'], ['CN', '"quoted"']],
  [['CN', 'sin organizacion']],
];

describe.skipIf(!oracleAvailable)('X500Principal.toString / getName parity with Java', () => {
  it('matches Java for tricky names', () => {
    const certs = NAMES.map((name, i) => {
      const ca = createCa(name, 'x500ca' + (i % 2));
      return issue(ca, [...name, ['CN', 'leaf ' + i]] as NameSpec, [
        ext.san({ email: i % 2 ? 'leaf' + i + '@example.ec' : undefined }),
      ]).cert;
    });
    const expected = oracleX500(certs);
    certs.forEach((c, i) => expect(jsX500(c), `name #${i}`).toEqual(expected[i]));
  });
});
