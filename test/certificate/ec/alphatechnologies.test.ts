import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as alpha from '../../../src/certificate/ec/alphatechnologies/index.js';
import * as certs from '../../../src/certificate/ec/alphatechnologies/certs.js';
import { createCa, ext, issue } from '../../helpers/pki.js';
import { oracleAvailable } from '../../helpers/oracle.js';
import { extFields, runMatrix, subjFull } from '../../helpers/ec-ext-subj.js';

const BASE = '1.3.6.1.4.1.56105';
const POLICIES = [
  alpha.Ext.OID_TIPO_PERSONA_NATURAL,
  alpha.Ext.OID_TIPO_PERSONA_JURIDICA,
  alpha.Ext.OID_TIPO_MIEMBRO_EMPRESA,
  alpha.Subj.OID_TIPO_PERSONA_NATURAL,
  alpha.Subj.OID_TIPO_MIEMBRO_EMPRESA,
  alpha.Subj.OID_TIPO_REPRESENTANTE_LEGAL,
];

describe.skipIf(!oracleAvailable)('Alpha Technologies parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    runMatrix(['ALPHA TECHNOLOGIES CIA. LTDA.', 'Alpha Technologies Cia. Ltda.'], 'alpha', BASE, POLICIES);
  });
});

describe('Alpha Technologies certs', () => {
  it('getRootCertificate returns null for test leaf certs', () => {
    const ca = createCa([['C', 'EC'], ['O', 'ALPHA TECHNOLOGIES CIA. LTDA.'], ['CN', 'SUBCA']], 'alpha-root');
    for (const p of POLICIES) {
      const leaf = issue(ca, subjFull, [ext.policies(p), ...extFields(BASE)]).cert;
      expect(alpha.getRootCertificate(new Certificate(leaf))).toBeNull();
    }
  });

  it('every embedded certificate parses', () => {
    for (const [name, c] of Object.entries(certs)) {
      expect(c, name).toBeInstanceOf(Certificate);
      expect(c.subjectPrincipal, name).toMatch(/\S/);
    }
  });
});
