import { describe, expect, it } from 'vitest';
import { der } from '../../../src/asn1/der.js';
import { Certificate } from '../../../src/x509/certificate.js';
import * as cj from '../../../src/certificate/ec/cj/index.js';
import * as certs from '../../../src/certificate/ec/cj/certs.js';
import { createCa, encodeString, ext, ExtSpec, issue, NameSpec, StringType } from '../../helpers/pki.js';
import { DatosResult, jsDatos, oracleAvailable, oracleDatos } from '../../helpers/oracle.js';

const CJ = '1.3.6.1.4.1.43745';
const ca = createCa([['C', 'EC'], ['O', 'CONSEJO DE LA JUDICATURA'], ['CN', 'SUBCA CJ TEST']], 'cj');
const caLower = createCa([['C', 'EC'], ['O', 'Consejo de la Judicatura'], ['CN', 'SUBCA CJ lower']], 'cj-lower');

const on = (n: string, value: Buffer) => ({ oid: `${CJ}.1.3.${n}`, value });
const str = (n: string, v: string, t: StringType = 'utf8') => on(n, encodeString(v, t));

/** Every field the classes read, as UTF8String otherNames. */
const sanUtf8 = ext.san({
  email: 'juan@funcionjudicial.gob.ec',
  otherNames: [
    str('1', '0102030405'),
    str('2', 'JUAN CARLOS'),
    str('3', 'PÉREZ'),
    str('4', 'ÑANDÚ'),
    str('5', 'JUEZ, "PRIMERO"'),
    str('6', 'FUNCIÓN JUDICIAL'),
    str('10', 'CONSEJO, DE LA "JUDICATURA"'),
    str('11', '1760001550001'),
    str('12', 'ECUADOR'),
  ],
});

/** Same fields with other inner value types (BouncyCastle toString emulation). */
const sanMixed = ext.san({
  otherNames: [
    str('1', 'IDCEC-0102030405', 'printable'),
    str('2', 'MARÍA JOSÉ', 'bmp'),
    on('3', der.octetString(Buffer.from('LOPEZ'))),
    on('4', der.sequence(der.utf8('GARCÍA'), der.printable('X'))),
    str('5', 'CONTADOR', 'ia5'),
    on('10', der.explicit(0, der.utf8('EMPRESA S.A.'))),
    on('11', der.integer(1790012345001)),
    str('12', 'EC', 't61'),
  ],
});

/** Only some fields; duplicate OID (first wins) and an unrelated otherName. */
const sanPartial = ext.san({
  dns: 'cj.gob.ec',
  otherNames: [
    { oid: '1.2.3.4.5', value: der.utf8('otro') },
    str('2', 'PRIMERO'),
    str('2', 'SEGUNDO'),
    str('11', 'VATEC-1790012345001'),
  ],
});

/** Tricky BouncyCastle toString cases. */
const sanTricky = ext.san({
  otherNames: [
    str('1', 'A[0]B[0]C [CONTEXT 0]D'),
    on('2', der.sequence(der.sequence(der.utf8('X'), der.bool(true)), der.null(), der.oid('1.2.3'))),
    on('3', der.set(der.utf8('B'), der.utf8('A'))),
    on('4', der.explicit(1, der.utf8('UNO'))),
    on('5', der.octetString(Buffer.from([0x00, 0xff, 0x10, 0xab]))),
    on('10', der.sequence()),
    on('11', der.explicit(0, der.explicit(0, der.printable('1790012345001')))),
    on('12', der.bool(false)),
  ],
});

const subj: NameSpec = [
  ['C', 'EC'],
  ['O', 'CONSEJO DE LA JUDICATURA'],
  ['SERIALNUMBER', '0102030405'],
  ['CN', 'JUAN CARLOS PÉREZ'],
];

const typePolicies = [
  '1.2.1.1.1.1',
  '1.2.1.1.1.2',
  '1.2.1.1.1.3',
  '1.2.1.1.2.1',
  '1.2.1.2.1.1',
  '1.2.1.2.1.2',
  '1.2.1.2.2.1',
  '1.2.1.3.1.1',
  '1.2.1.3.1.2',
  '1.2.1.3.1.3',
  '1.2.1.3.2.1',
  '1.2.1.4.1.1',
  '1.2.1.4.1.2',
  '1.2.1.4.1.3',
  '1.2.1.4.2.1',
  '1.2.2.1.1.2',
  '1.2.2.1.2.1',
  '1.2.3.1.1.2',
  '1.2.3.1.2.1',
  '1.2.4.1.1.3',
].map((p) => `${CJ}.${p}`);

const otherPolicies = [
  `${CJ}.1.2.9.9`, // matches the prefix pattern but no known type -> null
  `${CJ}.1.29`, // startsWith("1.3.6.1.4.1.43745.1.2") quirk -> null
  `${CJ}.1.1`, // prefix not matched -> null
  '1.2.3.4',
];

function sameAs(js: DatosResult, exp: DatosResult, label: string) {
  if (exp.error !== undefined) {
    // both threw
    expect(js.error, label + ' (java threw: ' + exp.error + ')').toBeDefined();
    expect(js.entidad, label).toEqual(exp.entidad);
  } else {
    expect(js, label).toEqual(exp);
  }
}

describe.skipIf(!oracleAvailable)('Consejo de la Judicatura parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    const certsDer: Buffer[] = [];
    const labels: string[] = [];
    const add = (label: string, c: Buffer) => {
      labels.push(label);
      certsDer.push(c);
    };
    const sans: Array<[string, ExtSpec | null]> = [
      ['utf8', sanUtf8],
      ['mixed', sanMixed],
      ['partial', sanPartial],
      ['tricky', sanTricky],
      ['nosan', null],
    ];
    for (const p of [...typePolicies, ...otherPolicies]) {
      for (const [sl, san] of sans) {
        const exts = [ext.policies(p), ext.string(`${CJ}.1.3.1`, 'EXT-NO-USADA')];
        if (san) exts.push(san);
        add(`${p} ${sl}`, issue(ca, subj, exts).cert);
      }
      add(`${p} lower-ca`, issue(caLower, subj, [ext.policies(p), sanUtf8]).cert);
      add(`${p} cn-only`, issue(ca, [['CN', 'SOLO CN']], [ext.policies(p)]).cert);
    }
    // several policies: first matching branch in construir order wins
    add('multi policies', issue(ca, subj, [ext.policies(`${CJ}.1.2.4.1.1.3`, `${CJ}.1.2.1.2.1.1`), sanUtf8]).cert);
    add('multi policies 2', issue(ca, subj, [ext.policies('1.2.3', `${CJ}.1.2.3.1.2.1`, `${CJ}.1.2.1.1.1.1`), sanMixed]).cert);
    // no extensions at all
    add('no extensions', issue(ca, subj, [], { withKeyUsage: false }).cert);

    const expected = oracleDatos(certsDer);
    certsDer.forEach((c, i) => sameAs(jsDatos(c), expected[i], `#${i} ${labels[i]}`));
  });
});

describe('Consejo de la Judicatura certs', () => {
  it('getRootCertificate returns null for test leaf certs', () => {
    const leaf = issue(ca, subj, [ext.policies(typePolicies[0]), sanUtf8]).cert;
    expect(cj.getRootCertificate(new Certificate(leaf))).toBeNull();
  });

  it('every embedded certificate parses', () => {
    for (const [name, c] of Object.entries(certs)) {
      expect(c, name).toBeInstanceOf(Certificate);
      expect(c.subjectPrincipal, name).toMatch(/\S/);
    }
  });
});
