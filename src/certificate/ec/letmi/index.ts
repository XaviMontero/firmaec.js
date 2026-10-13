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
import { SubCaCertLetmi20252035 } from './certs.js';

/** Port of `CertificadoLetmi` (OIDs). */
export const Subj = {
  OID_PERSONA_NATURAL_DSCF: '1.3.6.1.4.1.62566.2.1.2',
  OID_PERSONA_NATURAL_ARCHIVO: '1.3.6.1.4.1.62566.2.1.1',
  OID_REPRESENTANTE_LEGAL_DSCF: '1.3.6.1.4.1.62566.2.3.2',
  OID_REPRESENTANTE_LEGAL_ARCHIVO: '1.3.6.1.4.1.62566.2.3.1',
  OID_MIEMBRO_EMPRESA_DSCF: '1.3.6.1.4.1.62566.2.2.2',
  OID_MIEMBRO_EMPRESA_ARCHIVO: '1.3.6.1.4.1.62566.2.2.1',
  OID_SELLO_ELECTRONICO_DSCF: '1.3.6.1.4.1.62566.102.2.4.2',
  OID_SELLO_ELECTRONICO_ARCHIVO: '1.3.6.1.4.1.62566.102.2.4.1',
} as const;

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalLetmi extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaLetmi extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalLetmi extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelloElectronicoLetmi extends CertificadoSubjImpl {
  readonly tipos = tipos('SelloElectronico');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryLetmi.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertLetmi20252035)) return SubCaCertLetmi20252035;
  return null;
}

/** Port of `CertificadoDataFactoryLetmi.getDatosUsuarioLetmi`. */
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
  if (
    certificateHasPolicy(certificado, Subj.OID_PERSONA_NATURAL_DSCF) ||
    certificateHasPolicy(certificado, Subj.OID_PERSONA_NATURAL_ARCHIVO)
  ) {
    return new CertificadoSubjPersonaNaturalLetmi(certificado);
  } else if (
    certificateHasPolicy(certificado, Subj.OID_MIEMBRO_EMPRESA_DSCF) ||
    certificateHasPolicy(certificado, Subj.OID_MIEMBRO_EMPRESA_ARCHIVO)
  ) {
    return new CertificadoSubjMiembroEmpresaLetmi(certificado);
  } else if (
    certificateHasPolicy(certificado, Subj.OID_REPRESENTANTE_LEGAL_DSCF) ||
    certificateHasPolicy(certificado, Subj.OID_REPRESENTANTE_LEGAL_ARCHIVO)
  ) {
    return new CertificadoSubjRepresentanteLegalLetmi(certificado);
  } else if (
    certificateHasPolicy(certificado, Subj.OID_SELLO_ELECTRONICO_DSCF) ||
    certificateHasPolicy(certificado, Subj.OID_SELLO_ELECTRONICO_ARCHIVO)
  ) {
    return new CertificadoSubjSelloElectronicoLetmi(certificado);
  }
  return null;
}
