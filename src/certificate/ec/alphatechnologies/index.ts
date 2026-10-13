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
import { Certificado, esMiembroEmpresa, esPersonaNatural, esRepresentanteLegal, tipos } from '../../base.js';
import { certificateHasPolicy, hasExtensionMatchingPattern, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import { SubCaCertAlphaTechnologies20232026, SubCaCertAlphaTechnologies20242032 } from './certs.js';

/** Port of `CertificadoAlphaTechnologies` (OIDs). */
export const Subj = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.56105.2.1.1',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.56105.2.2.1',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.56105.2.3.1',
} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.56105.2.1',
  OID_TIPO_PERSONA_JURIDICA: '1.3.6.1.4.1.56105.2.2',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.56105.2.3',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.56105.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.56105.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.56105.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.56105.3.4',
  OID_CARGO: '1.3.6.1.4.1.56105.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.56105.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.56105.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.56105.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.56105.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.56105.3.10',
  OID_RUC: '1.3.6.1.4.1.56105.3.11',
  OID_PAIS: '1.3.6.1.4.1.56105.3.12',
} as const;

// ------------------------------------------------------------------ ext

export class CertificadoExtImplAlphaTechnologies extends Certificado {
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

export class CertificadoExtPersonaNaturalAlphaTechnologies extends CertificadoExtImplAlphaTechnologies {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtMiembroEmpresaAlphaTechnologies extends CertificadoExtImplAlphaTechnologies {
  override readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

export class CertificadoExtPersonaJuridicaAlphaTechnologies extends CertificadoExtImplAlphaTechnologies {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalAlphaTechnologies extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaAlphaTechnologies extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalAlphaTechnologies extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryAlphaTechnologies.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertAlphaTechnologies20232026)) return SubCaCertAlphaTechnologies20232026;
  if (verifySignature(certificado, SubCaCertAlphaTechnologies20242032)) return SubCaCertAlphaTechnologies20242032;
  return null;
}

/** Port of `CertificadoDataFactoryAlphaTechnologies.getDatosUsuarioAlphaTechnologies`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplAlphaTechnologies) {
      datosUsuario.setTipoCertificado('Persona Natural (EXT)');
      if (c instanceof CertificadoExtPersonaNaturalAlphaTechnologies) {
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtMiembroEmpresaAlphaTechnologies) {
        datosUsuario.setTipoCertificado('Miembro Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtPersonaJuridicaAlphaTechnologies) {
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
    }
    datosUsuario.setCertificadoDigitalValido(true);
  }
  return datosUsuario;
}

function construir(certificado: Certificate): Certificado | null {
  if (hasExtensionMatchingPattern(certificado, '1.3.6.1.4.1', '3.1')) {
    if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoExtPersonaNaturalAlphaTechnologies(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
      return new CertificadoExtPersonaJuridicaAlphaTechnologies(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
      return new CertificadoExtMiembroEmpresaAlphaTechnologies(certificado);
    }
  } else {
    // RESOLUCION-ARCOTEL-2024-0176
    if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoSubjPersonaNaturalAlphaTechnologies(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
      return new CertificadoSubjMiembroEmpresaAlphaTechnologies(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
      return new CertificadoSubjRepresentanteLegalAlphaTechnologies(certificado);
    }
  }
  return null;
}
