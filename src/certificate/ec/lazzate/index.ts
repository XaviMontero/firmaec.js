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
import {
  Certificado,
  esMiembroEmpresa,
  esPersonaNatural,
  esRepresentanteLegal,
  esSelloElectronico,
  tipos,
} from '../../base.js';
import { certificateHasPolicy, hasExtensionMatchingPattern, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import { SubCa1CertLazzate, SubCa2CertLazzate, SubCaCertLazzate, SubCaWeGoCertLazzate } from './certs.js';

/** Port of `CertificadoLazzate` (OIDs). */
export const Subj = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.59382.2.1.1',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.59382.2.2.1',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.59382.2.3.1',
  OID_TIPO_SELLO_ELECTRONICO: '1.3.6.1.4.1.59382.102.2.4.1',
} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.59382.2.1',
  OID_TIPO_PERSONA_JURIDICA_EMPRESA: '1.3.6.1.4.1.59382.2.2',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.59382.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.59382.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.59382.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.59382.3.4',
  OID_CARGO: '1.3.6.1.4.1.59382.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.59382.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.59382.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.59382.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.59382.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.59382.3.10',
  OID_RUC: '1.3.6.1.4.1.59382.3.11',
  OID_PAIS: '1.3.6.1.4.1.59382.3.12',
} as const;

// ------------------------------------------------------------------ ext

export class CertificadoExtImplLazzate extends Certificado {
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

export class CertificadoExtPersonaNaturalLazzate extends CertificadoExtImplLazzate {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtPersonaJuridicaLazzate extends CertificadoExtImplLazzate {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalLazzate extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaLazzate extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalLazzate extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelloElectronicoLazzate extends CertificadoSubjImpl {
  readonly tipos = tipos('SelloElectronico');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryLazzate.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertLazzate)) return SubCaCertLazzate;
  if (verifySignature(certificado, SubCa1CertLazzate)) return SubCa1CertLazzate;
  if (verifySignature(certificado, SubCa2CertLazzate)) return SubCa2CertLazzate;
  if (verifySignature(certificado, SubCaWeGoCertLazzate)) return SubCaWeGoCertLazzate;
  return null;
}

/** Port of `CertificadoDataFactoryLazzate.getDatosUsuarioLazzate`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplLazzate) {
      if (c instanceof CertificadoExtPersonaNaturalLazzate) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtPersonaJuridicaLazzate) {
        datosUsuario.setTipoCertificado('Persona Jurídica (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
    }
    // RESOLUCION-ARCOTEL-2024-0176
    if (c instanceof CertificadoSubjImpl) {
      // Java: instanceof over the marker interfaces (which inherit from CertificadoPersonaNatural)
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
        datosUsuario.setTipoCertificado('Sello Electrónico');
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCommonName(c.getCommonName());
      }
    }
    datosUsuario.setCertificadoDigitalValido(true);
  }
  return datosUsuario;
}

function construir(certificado: Certificate): Certificado | null {
  if (hasExtensionMatchingPattern(certificado, '1.3.6.1.4.1', '3.1')) {
    if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoExtPersonaNaturalLazzate(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_EMPRESA)) {
      return new CertificadoExtPersonaJuridicaLazzate(certificado);
    }
  } else {
    // RESOLUCION-ARCOTEL-2024-0176
    if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoSubjPersonaNaturalLazzate(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
      return new CertificadoSubjMiembroEmpresaLazzate(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
      return new CertificadoSubjRepresentanteLegalLazzate(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)) {
      return new CertificadoSubjSelloElectronicoLazzate(certificado);
    }
  }
  return null;
}
