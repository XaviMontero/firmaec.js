/**
 * Shared certificate matrix for the CAs whose `construir` switches between
 * extension based ("EXT", `hasExtensionMatchingPattern(cert, "1.3.6.1.4.1", "3.1")`)
 * and subject based (RESOLUCION-ARCOTEL-2024-0176) certificates
 * (Lazzate, Alpha Technologies, FirmaSegura).
 */
import { expect } from 'vitest';
import { der } from '../../src/asn1/der.js';
import { createCa, ext, ExtSpec, issue, NameSpec, StringType, TestCa } from './pki.js';
import { DatosResult, jsDatos, oracleDatos } from './oracle.js';

export function sameAs(js: DatosResult, exp: DatosResult, label: string) {
  if (exp.error !== undefined) {
    // both threw
    expect(js.error, label + ' (java threw: ' + exp.error + ')').toBeDefined();
    expect(js.entidad, label).toEqual(exp.entidad);
  } else {
    expect(js, label).toEqual(exp);
  }
}

/** Extension fields `<base>.3.<n>` (cedula .. pais) with the given string type. */
export function extFields(base: string, t: StringType = 'utf8'): ExtSpec[] {
  return [
    ext.string(`${base}.3.1`, 'IDCEC-1712345678', t === 'bmp' ? 'bmp' : 'printable'),
    ext.string(`${base}.3.2`, t === 'printable' ? 'JUAN CARLOS' : 'JUAN CARLOS ÁLVAREZ', t),
    ext.string(`${base}.3.3`, t === 'printable' ? 'PEREZ' : 'PÉREZ', t),
    ext.string(`${base}.3.4`, t === 'printable' ? 'NANDU' : 'ÑANDÚ "Ñ"', t),
    ext.string(`${base}.3.5`, t === 'printable' ? 'GERENTE, GENERAL' : 'GERENTE, "GENERAL"', t),
    ext.string(`${base}.3.6`, 'INSTITUCION', t),
    ext.string(`${base}.3.7`, 'AV. AMAZONAS N1-23', t),
    ext.string(`${base}.3.8`, '022222222', t),
    ext.string(`${base}.3.9`, 'QUITO', t),
    ext.string(`${base}.3.10`, t === 'printable' ? 'EMPRESA S.A.' : 'EMPRESA, S.A. "Ñ"', t),
    ext.string(`${base}.3.11`, 'VATEC-1790012345001', t === 'bmp' ? 'bmp' : 'printable'),
    ext.string(`${base}.3.12`, 'ECUADOR', t),
  ];
}

/** Only the cedula extension, plus non string values for some fields. */
export function extOdd(base: string): ExtSpec[] {
  return [
    ext.string(`${base}.3.1`, '0102030405', 'ia5'),
    ext.raw(`${base}.3.2`, der.integer(12345)),
    ext.raw(`${base}.3.3`, der.sequence(der.utf8('SEQ'))),
    ext.raw(`${base}.3.10`, der.octetString(Buffer.from('OCTETS'))),
    ext.string(`${base}.3.11`, 'VATEC-1790012345001', 't61'),
  ];
}

export const subjFull: NameSpec = [
  ['C', 'EC'],
  ['L', 'QUITO'],
  ['O', 'EMPRESA, S.A. "Ñ"'],
  ['OU', 'SISTEMAS'],
  ['T', 'CONTADOR'],
  ['2.5.4.97', 'VATEC-1790012345001'],
  ['SERIALNUMBER', 'IDCEC-1712345678'],
  ['GN', 'MARÍA JOSÉ'],
  ['SN', 'LÓPEZ GARCÍA'],
  ['CN', 'MARÍA JOSÉ LÓPEZ'],
];

export const subjBmp: NameSpec = [
  ['C', 'EC'],
  ['O', 'ÑANDÚ CÍA. LTDA.', 'bmp'],
  ['T', 'GERENTE', 'printable'],
  ['2.5.4.97', 'VATEC-0990012345001', 'printable'],
  ['SERIALNUMBER', 'PASEC-A1234567'],
  [
    ['GN', 'ANA', 'bmp'],
    ['SN', 'ÑUÑEZ', 'bmp'],
  ],
  ['CN', 'ANA ÑUÑEZ, "LA JEFA"', 'bmp'],
];

export const subjCn: NameSpec = [['CN', 'SOLO CN']];

/**
 * Builds the matrix and compares every cert with the Java oracle.
 * @param issuerOrgs every O value that getNombreCA maps to the CA
 * @param base the CA private enterprise arc, e.g. `1.3.6.1.4.1.59382`
 * @param policies every policy OID used by `construir` (Ext and Subj)
 */
export function runMatrix(issuerOrgs: string[], label: string, base: string, policies: string[]) {
  const cas: TestCa[] = issuerOrgs.map((o, i) => createCa([['C', 'EC'], ['O', o], ['CN', `SUBCA ${label} ${i}`]], `${label}-${i}`));
  const ca = cas[0];
  const allPolicies = [...policies, `${base}.2.9.9`, '1.2.3.4'];
  const certs: Buffer[] = [];
  const labels: string[] = [];
  const add = (l: string, c: Buffer) => {
    labels.push(l);
    certs.push(c);
  };
  const extSets: Array<[string, ExtSpec[]]> = [
    ['ext-utf8', extFields(base)],
    ['ext-printable', extFields(base, 'printable')],
    ['ext-bmp', extFields(base, 'bmp')],
    ['ext-odd', extOdd(base)],
    // only an unrelated extension matching the "1.3.6.1.4.1"/"3.1" pattern (".13.1" ends with "3.1")
    ['ext-trigger-only', [ext.string('1.3.6.1.4.1.99999.13.1', 'X')]],
    // CA fields but none ends with "3.1": subject branch
    ['ext-no-trigger', extFields(base).filter((e) => !e.oid.endsWith('3.1'))],
    ['no-ext', []],
  ];
  const subjects: Array<[string, NameSpec]> = [
    ['subj-full', subjFull],
    ['subj-bmp', subjBmp],
    ['subj-cn', subjCn],
  ];
  for (const p of allPolicies) {
    for (const [el, exts] of extSets) {
      for (const [sl, s] of subjects) {
        add(`${p} ${el} ${sl}`, issue(ca, s, [ext.policies(p), ...exts, ext.san({ email: 'a@b.ec' })]).cert);
      }
    }
    for (const other of cas.slice(1)) {
      add(`${p} issuer-variant`, issue(other, subjFull, [ext.policies(p), ...extFields(base)]).cert);
      add(`${p} issuer-variant subj`, issue(other, subjFull, [ext.policies(p)]).cert);
    }
  }
  // several policies at once: order of the if chain wins
  add('multi policies ext', issue(ca, subjFull, [ext.policies(...[...policies].reverse()), ...extFields(base)]).cert);
  add('multi policies subj', issue(ca, subjFull, [ext.policies(...[...policies].reverse())]).cert);
  // no extensions at all
  add('no extensions', issue(ca, subjFull, [], { withKeyUsage: false }).cert);

  const expected = oracleDatos(certs);
  certs.forEach((c, i) => sameAs(jsDatos(c), expected[i], `#${i} ${labels[i]}`));
  return { ca, count: certs.length };
}
