import { describe, expect, it } from 'vitest';
import { Certificate } from '../../../src/x509/certificate.js';
import * as fs from '../../../src/certificate/ec/firmasegura/index.js';
import * as certs from '../../../src/certificate/ec/firmasegura/certs.js';
import { createCa, ext, issue } from '../../helpers/pki.js';
import { oracleAvailable } from '../../helpers/oracle.js';
import { extFields, runMatrix, subjFull } from '../../helpers/ec-ext-subj.js';

const BASE = '1.3.6.1.4.1.61305';
// Note: Ext.OID_TIPO_PERSONA_NATURAL / REPRESENTANTE_LEGAL equal Subj.OID_TIPO_MIEMBRO_EMPRESA(_DSCF) in Java
const POLICIES = [
  fs.Ext.OID_TIPO_PERSONA_NATURAL,
  fs.Ext.OID_TIPO_REPRESENTANTE_LEGAL,
  fs.Subj.OID_TIPO_PERSONA_NATURAL,
  fs.Subj.OID_TIPO_PERSONA_NATURAL_DSCF,
  fs.Subj.OID_TIPO_MIEMBRO_EMPRESA,
  fs.Subj.OID_TIPO_MIEMBRO_EMPRESA_DSCF,
  fs.Subj.OID_TIPO_REPRESENTANTE_LEGAL,
  fs.Subj.OID_TIPO_REPRESENTANTE_LEGAL_DSCF,
];

describe.skipIf(!oracleAvailable)('FirmaSegura parity with Java', () => {
  it('extracts the same DatosUsuario for every certificate type', () => {
    runMatrix(['FIRMASEGURA S.A.S.', 'FirmaSegura S.A.S.'], 'firmasegura', BASE, POLICIES);
  });
});

describe('FirmaSegura certs', () => {
  it('getRootCertificate returns null for test leaf certs', () => {
    const ca = createCa([['C', 'EC'], ['O', 'FIRMASEGURA S.A.S.'], ['CN', 'SUBCA']], 'firmasegura-root');
    for (const p of POLICIES) {
      const leaf = issue(ca, subjFull, [ext.policies(p), ...extFields(BASE)]).cert;
      expect(fs.getRootCertificate(new Certificate(leaf))).toBeNull();
    }
  });

  it('every embedded certificate parses', () => {
    for (const [name, c] of Object.entries(certs)) {
      expect(c, name).toBeInstanceOf(Certificate);
      expect(c.subjectPrincipal, name).toMatch(/\S/);
    }
  });
});
