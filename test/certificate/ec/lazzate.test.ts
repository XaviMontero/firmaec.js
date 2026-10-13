import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as lazzate from '../../../src/certificate/ec/lazzate/index.js';
import * as certs from '../../../src/certificate/ec/lazzate/certs.js';
import { createCa, ext, issue } from '../../helpers/pki.js';
import { oracleAvailable } from '../../helpers/oracle.js';
import { extFields, runMatrix, subjFull } from '../../helpers/ec-ext-subj.js';

const BASE = '1.3.6.1.4.1.59382';
const POLICIES = [
  lazzate.Ext.OID_TIPO_PERSONA_NATURAL,
  lazzate.Ext.OID_TIPO_PERSONA_JURIDICA_EMPRESA,
  lazzate.Subj.OID_TIPO_PERSONA_NATURAL,
  lazzate.Subj.OID_TIPO_MIEMBRO_EMPRESA,
  lazzate.Subj.OID_TIPO_REPRESENTANTE_LEGAL,
  lazzate.Subj.OID_TIPO_SELLO_ELECTRONICO,
];

describe.skipIf(!oracleAvailable)('Lazzate parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    runMatrix(['LAZZATE CIA. LTDA.', 'Lazzate Cia. Ltda.'], 'lazzate', BASE, POLICIES);
  });
});

describe('Lazzate certs', () => {
  it('getRootCertificate returns null for test leaf certs', () => {
    const ca = createCa([['C', 'EC'], ['O', 'LAZZATE CIA. LTDA.'], ['CN', 'SUBCA']], 'lazzate-root');
    for (const p of POLICIES) {
      const leaf = issue(ca, subjFull, [ext.policies(p), ...extFields(BASE)]).cert;
      expect(lazzate.getRootCertificate(new Certificate(leaf))).toBeNull();
    }
  });

  it('every embedded certificate parses', () => {
    for (const [name, c] of Object.entries(certs)) {
      expect(c, name).toBeInstanceOf(Certificate);
      expect(c.subjectPrincipal, name).toMatch(/\S/);
    }
  });
});
