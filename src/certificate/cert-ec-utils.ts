/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import { EntidadCertificadoraNoValidaException } from '../errors.js';
import { Certificate } from '../x509/certificate.js';
import { getEmail, getRDNvalueFromLdapName } from './cert-utils.js';
import { DatosUsuario } from './datos-usuario.js';
import * as alphatechnologies from './ec/alphatechnologies/index.js';
import * as anfac from './ec/anfac/index.js';
import * as appfirmas from './ec/appfirmas/index.js';
import * as argosdata from './ec/argosdata/index.js';
import * as bce from './ec/bce/index.js';
import * as cj from './ec/cj/index.js';
import * as corpnewbest from './ec/corpnewbest/index.js';
import * as darkcam from './ec/darkcam/index.js';
import * as datil from './ec/datil/index.js';
import * as digercic from './ec/digercic/index.js';
import * as eclipsoft from './ec/eclipsoft/index.js';
import * as firmasegura from './ec/firmasegura/index.js';
import * as lazzate from './ec/lazzate/index.js';
import * as letmi from './ec/letmi/index.js';
import * as primecorelat from './ec/primecorelat/index.js';
import * as securitydata from './ec/securitydata/index.js';
import * as uanataca from './ec/uanataca/index.js';

/** Port of `certificate.CertEcUtils`. */
export const ALPHATECHNOLOGIES_NAME = 'ALPHA TECHNOLOGIES CIA. LTDA.';
export const ANFAC_NAME = 'ANFAC AUTORIDAD DE CERTIFICACION ECUADOR C.A.';
export const ANFAC_NAME_OLD = 'ANFAC AUTORIDAD DE CERTIFICACION ECUADOR CA';
export const APPFIRMAS_NAME = 'APPFIRMAS S.A.';
export const APPFIRMAS_NAME_OLD = 'APPFIRMAS S.A. SUB CA';
export const AGOSDATA_NAME = 'ARGOSDATA CERTIFICACIÓN DE INFORMACIÓN Y SERVICIOS RELACIONADOS';
export const AGOSDATA_NAME_OLD = 'ARGOSDATA';
export const BCE_NAME = 'BANCO CENTRAL DEL ECUADOR';
export const CJ_NAME = 'CONSEJO DE LA JUDICATURA';
export const CORPNEWBEST_NAME = 'CORPNEWBEST CIA. LTDA.';
export const DARKCAM_NAME = 'DARKCAM S.A.';
export const DATIL_NAME = 'DATILMEDIA S.A.';
export const DIGERCIC_NAME = 'DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN Y CEDULACIÓN';
export const ECLIPSOFT_NAME = 'ECLIPSOFT S.A.';
export const FIRMASEGURA_NAME = 'FIRMASEGURA S.A.S.';
export const LAZZATE_NAME = 'LAZZATE CIA. LTDA.';
export const LETMI_NAME = 'LETMI ECUADOR S.A.';
export const PRIMECORELAT_NAME = 'PRIMECORELAT S.A.S. B.I.C.';
export const SECURITYDATA_NAME = 'SECURITY DATA SEGURIDAD EN DATOS Y FIRMA DIGITAL S.A.';
export const SECURITYDATA_NAME_OLD = 'SECURITY DATA';
export const UANATACA_NAME = 'UANATACA ECUADOR S.A.';
export const UANATACA_NAME_OLD = 'UANATACA S.A.';
export const ECLIPSOFT_COMMON_NAME = 'UANATACA CA1 2016';

/** Java `String.toUpperCase()` (locale independent for these names). */
const upper = (s: string) => s.toUpperCase();

/** Identifies the Ecuadorian CA from the issuer organization (O). */
export function getNombreCA(certificado: Certificate): string {
  const issuer = certificado.issuerPrincipal;
  // Java would throw a NullPointerException when the issuer has no O
  const organization = getRDNvalueFromLdapName('O', issuer);
  if (organization === null) {
    throw new EntidadCertificadoraNoValidaException('NullPointerException: emisor sin organización (O)');
  }
  const o = upper(organization);
  if (o === ALPHATECHNOLOGIES_NAME) return ALPHATECHNOLOGIES_NAME;
  if (o === ANFAC_NAME) return ANFAC_NAME;
  if (o === ANFAC_NAME_OLD) return ANFAC_NAME_OLD;
  if (o === APPFIRMAS_NAME) return APPFIRMAS_NAME;
  if (o === APPFIRMAS_NAME_OLD) return APPFIRMAS_NAME_OLD;
  if (o.includes(AGOSDATA_NAME)) return AGOSDATA_NAME;
  if (o === AGOSDATA_NAME_OLD) return AGOSDATA_NAME_OLD;
  if (o === BCE_NAME) return BCE_NAME;
  if (o === CJ_NAME) return CJ_NAME;
  if (o === CORPNEWBEST_NAME) return CORPNEWBEST_NAME;
  if (o === DARKCAM_NAME) return DARKCAM_NAME;
  if (o === DATIL_NAME) return DATIL_NAME;
  if (o === DIGERCIC_NAME) return DIGERCIC_NAME;
  if (o === ECLIPSOFT_NAME) return ECLIPSOFT_NAME;
  if (o === FIRMASEGURA_NAME) return FIRMASEGURA_NAME;
  if (o === LAZZATE_NAME) return LAZZATE_NAME;
  if (o === LETMI_NAME) return LETMI_NAME;
  if (o === PRIMECORELAT_NAME) return PRIMECORELAT_NAME;
  if (o === SECURITYDATA_NAME) return SECURITYDATA_NAME;
  if (o.includes(SECURITYDATA_NAME_OLD)) return SECURITYDATA_NAME_OLD;
  if (o === UANATACA_NAME) return UANATACA_NAME;
  if (o.includes(UANATACA_NAME_OLD)) {
    const commonName = getRDNvalueFromLdapName('CN', issuer);
    if (commonName !== null && upper(commonName) === ECLIPSOFT_COMMON_NAME) return ECLIPSOFT_NAME;
    return UANATACA_NAME_OLD;
  }
  return 'Entidad no reconocida ' + certificado.issuer.toRfc2253();
}

interface CaModule {
  getRootCertificate(c: Certificate): Certificate | null;
  getDatosUsuario(c: Certificate): DatosUsuario | null;
}

/** CA name -> [module for root certificate, module for user data] (as dispatched in Java). */
const DISPATCH: Record<string, [CaModule, CaModule]> = {
  [ALPHATECHNOLOGIES_NAME]: [alphatechnologies, alphatechnologies],
  [ANFAC_NAME]: [anfac, anfac],
  [ANFAC_NAME_OLD]: [anfac, anfac],
  [APPFIRMAS_NAME]: [appfirmas, appfirmas],
  [APPFIRMAS_NAME_OLD]: [appfirmas, appfirmas],
  [AGOSDATA_NAME]: [argosdata, argosdata],
  [AGOSDATA_NAME_OLD]: [argosdata, argosdata],
  [BCE_NAME]: [bce, bce],
  [CJ_NAME]: [cj, cj],
  [CORPNEWBEST_NAME]: [corpnewbest, corpnewbest],
  [DARKCAM_NAME]: [darkcam, darkcam],
  [DATIL_NAME]: [datil, datil],
  // Java: DIGERCIC uses its own root certificates but Datil's user data parser
  [DIGERCIC_NAME]: [digercic, datil],
  [ECLIPSOFT_NAME]: [eclipsoft, eclipsoft],
  [FIRMASEGURA_NAME]: [firmasegura, firmasegura],
  [LAZZATE_NAME]: [lazzate, lazzate],
  [LETMI_NAME]: [letmi, letmi],
  [PRIMECORELAT_NAME]: [primecorelat, primecorelat],
  [SECURITYDATA_NAME]: [securitydata, securitydata],
  [SECURITYDATA_NAME_OLD]: [securitydata, securitydata],
  [UANATACA_NAME]: [uanataca, uanataca],
  [UANATACA_NAME_OLD]: [uanataca, uanataca],
};

/** Port of `CertEcUtils.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  const entry = DISPATCH[getNombreCA(certificado)];
  if (!entry) throw new EntidadCertificadoraNoValidaException('Entidad Certificadora no reconocida');
  return entry[0].getRootCertificate(certificado);
}

/** Port of `CertEcUtils.getDatosUsuarios`. */
export function getDatosUsuarios(certificado: Certificate): DatosUsuario | null {
  const entry = DISPATCH[getNombreCA(certificado)];
  if (!entry) throw new EntidadCertificadoraNoValidaException('Entidad Certificadora no reconocida');
  const datosUsuario = entry[1].getDatosUsuario(certificado);
  if (datosUsuario !== null) {
    datosUsuario.setEmail(getEmail(certificado));
  }
  return datosUsuario;
}
