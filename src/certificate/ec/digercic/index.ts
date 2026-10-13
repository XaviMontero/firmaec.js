/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import { EntidadCertificadoraNoValidaException } from '../../../errors.js';
import { Certificate } from '../../../x509/certificate.js';
import { Certificado, tipos } from '../../base.js';
import { certificateHasPolicy, getCN, hasExtensionMatchingPattern, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { SubCaCertDigercic20212031 } from './certs.js';

/** Port of `CertificadoDigercic` (OIDs). The Java `Subj` class is empty (all commented out). */
export const Subj = {} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.55519.1.1.1.5.3.2',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.55519.1.1.1.5.3.4',
  OID_CEDULA: '1.3.6.1.4.1.55519.1.1.1.5.2.1',
  OID_PASAPORTE: '1.3.6.1.4.1.55519.1.1.1.5.2.2',
  OID_APELLIDO: '1.3.6.1.4.1.55519.1.1.1.5.2.3',
  OID_RUC: '1.3.6.1.4.1.55519.1.1.1.5.2.4',
} as const;

// ------------------------------------------------------------------ ext

export class CertificadoExtImplDigercic extends Certificado {
  readonly tipos = tipos();

  getCedulaPasaporte(): string {
    return this.getExtensionField(Ext.OID_CEDULA);
  }

  getNombres(): string {
    return this.getExtensionField('');
  }

  getPrimerApellido(): string {
    return this.getExtensionField(Ext.OID_APELLIDO);
  }

  getSegundoApellido(): string {
    return this.getExtensionField('');
  }

  getDireccion(): string {
    return this.getExtensionField('');
  }

  getTelefono(): string {
    return this.getExtensionField('');
  }

  getCiudad(): string {
    return this.getExtensionField('');
  }

  getPais(): string {
    return this.getExtensionField('');
  }

  getRuc(): string {
    return this.getExtensionField(Ext.OID_RUC);
  }
}

export class CertificadoExtPersonaNaturalDigercic extends CertificadoExtImplDigercic {
  override readonly tipos = tipos('PersonaNatural');
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryDigercic.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertDigercic20212031)) return SubCaCertDigercic20212031;
  return null;
}

/**
 * Port of `CertificadoDataFactoryDigercic.getDatosUsuarioDatil` (sic). Note: the
 * Java `CertEcUtils` dispatcher does NOT call this for DIGERCIC certificates, it
 * uses Datil's factory instead.
 */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplDigercic) {
      if (c instanceof CertificadoExtPersonaNaturalDigercic) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(getCN(certificado));
        datosUsuario.setApellido('');
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
      return new CertificadoExtPersonaNaturalDigercic(certificado);
    } else {
      throw new EntidadCertificadoraNoValidaException(
        'Certificado de DIRECCIÓN GENERAL DE REGISTRO CIVIL, IDENTIFICACIÓN sin categorizar!',
      );
    }
  }
  return null;
}
