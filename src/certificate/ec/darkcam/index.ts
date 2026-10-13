/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import { Certificate } from '../../../x509/certificate.js';
import { Certificado, esMiembroEmpresa, esPersonaNatural, esRepresentanteLegal, esSelloElectronico, tipos } from '../../base.js';
import { certificateHasPolicy, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import { SubCaCertDarkcam20262036, SubCaShortCertDarkcam20262036 } from './certs.js';

/** Port of `CertificadoDarkcam` (OIDs). */
export const Subj = {
  // Persona Natural (SIN RUC y CON RUC usan el mismo OID, se diferencian por Organization Identifier 2.5.4.97)
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.64482.2.1.1',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.64482.2.2.1',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.64482.2.3.1',
  OID_TIPO_SELLO_ELECTRONICO: '1.3.6.1.4.1.64482.2.2.2',
} as const;

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalDarkcam extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaDarkcam extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalDarkcam extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelloElectronicoDarkcam extends CertificadoSubjImpl {
  readonly tipos = tipos('SelloElectronico');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryDarkcam.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaShortCertDarkcam20262036)) return SubCaShortCertDarkcam20262036;
  if (verifySignature(certificado, SubCaCertDarkcam20262036)) return SubCaCertDarkcam20262036;
  return null;
}

/** Port of `CertificadoDataFactoryDarkcam.getDatosUsuarioDarkcam`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    // RESOLUCION-ARCOTEL-2024-0176
    if (c instanceof CertificadoSubjImpl) {
      if (esPersonaNatural(c)) {
        datosUsuario.setTipoCertificado('Persona Natural');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido());
      }
      if (esMiembroEmpresa(c)) {
        datosUsuario.setTipoCertificado('Miembro Empresa');
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (esRepresentanteLegal(c)) {
        datosUsuario.setTipoCertificado('Representante Legal');
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (esSelloElectronico(c)) {
        datosUsuario.setTipoCertificado('Sellado Electrónico');
        datosUsuario.setCommonName(c.getCommonName());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
      }
    }
    datosUsuario.setCertificadoDigitalValido(true);
  }
  return datosUsuario;
}

function construir(certificado: Certificate): Certificado | null {
  // Persona Natural (con o sin RUC - se diferencian por presencia del campo Organization Identifier 2.5.4.97)
  if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
    return new CertificadoSubjPersonaNaturalDarkcam(certificado);
  } // Miembro de Empresa
  else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
    return new CertificadoSubjMiembroEmpresaDarkcam(certificado);
  } // Representante Legal
  else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
    return new CertificadoSubjRepresentanteLegalDarkcam(certificado);
  } // Sello Electrónico
  else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)) {
    return new CertificadoSubjSelloElectronicoDarkcam(certificado);
  }
  return null;
}
