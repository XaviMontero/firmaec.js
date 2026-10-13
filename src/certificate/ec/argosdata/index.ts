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
import { Certificado, tipos } from '../../base.js';
import { certificateHasPolicy, hasExtensionMatchingPattern, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import { SubCaCertArgosData20242032, SubCaCertArgosData20262036 } from './certs.js';

/** Port of `CertificadoArgosData` (OIDs). */
export const Subj = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.59198.2.1.1',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.59198.2.2.1',
} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.59198.2.1.1',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.59198.2.2.1',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.59198.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.59198.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.59198.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.59198.3.4',
  OID_CARGO: '1.3.6.1.4.1.59198.3.5',
  OID_DIRECCION: '1.3.6.1.4.1.59198.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.59198.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.59198.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.59198.3.10',
  OID_RUC: '1.3.6.1.4.1.59198.3.11',
  OID_PAIS: '1.3.6.1.4.1.59198.3.12',
} as const;

// ------------------------------------------------------------------ ext

export class CertificadoExtImplArgosData extends Certificado {
  readonly tipos = tipos();

  getCedulaPasaporte(): string {
    return this.getExtensionField(Ext.OID_CEDULA_PASAPORTE);
  }

  getNombres(): string {
    return this.getExtensionField(Ext.OID_NOMBRES);
  }

  getPrimerApellido(): string {
    return this.getExtensionField(Ext.OID_APELLIDO_1);
  }

  getSegundoApellido(): string {
    return this.getExtensionField(Ext.OID_APELLIDO_2);
  }

  getDireccion(): string {
    return this.getExtensionField(Ext.OID_DIRECCION);
  }

  getTelefono(): string {
    return this.getExtensionField(Ext.OID_TELEFONO);
  }

  getCiudad(): string {
    return this.getExtensionField(Ext.OID_CIUDAD);
  }

  getPais(): string {
    return this.getExtensionField(Ext.OID_PAIS);
  }

  getRuc(): string {
    return this.getExtensionField(Ext.OID_RUC);
  }
}

export class CertificadoExtPersonaNaturalArgosData extends CertificadoExtImplArgosData {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtRepresentanteLegalArgosData extends CertificadoExtImplArgosData {
  override readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

// ------------------------------------------------------------------ subj
// (not used by the factory: the RESOLUCION-ARCOTEL-2024-0176 branch is commented out in Java)

export class CertificadoSubjPersonaNaturalArgosData extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjRepresentanteLegalArgosData extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryArgosData.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertArgosData20242032)) return SubCaCertArgosData20242032;
  if (verifySignature(certificado, SubCaCertArgosData20262036)) return SubCaCertArgosData20262036;
  return null;
}

/** Port of `CertificadoDataFactoryArgosData.getDatosUsuarioArgosData`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplArgosData) {
      if (c instanceof CertificadoExtPersonaNaturalArgosData) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtRepresentanteLegalArgosData) {
        datosUsuario.setTipoCertificado('Representante Legal (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
    }
    // RESOLUCION-ARCOTEL-2024-0176: commented out in Java
    datosUsuario.setCertificadoDigitalValido(true);
  }
  return datosUsuario;
}

function construir(certificado: Certificate): Certificado | null {
  if (hasExtensionMatchingPattern(certificado, '1.3.6.1.4.1', '3.1')) {
    if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoExtPersonaNaturalArgosData(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)) {
      return new CertificadoExtRepresentanteLegalArgosData(certificado);
    }
    // RESOLUCION-ARCOTEL-2024-0176 else branch: commented out in Java
  }
  return null;
}
