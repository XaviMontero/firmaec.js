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
import { certificateHasPolicy, hasCertificatePoliciesMatchingPattern, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
// Java: Eclipsoft has no cert/ package, it reuses the Uanataca sub CAs
import { SubCaCertUanataca0120162029, SubCaCertUanataca0220162029, SubCaCertUanataca0320212034 } from '../uanataca/certs.js';

/** Port of `CertificadoEclipsoft` (OIDs). `Subj` is empty in Java (all OIDs commented out). */
export const Subj = {} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL_ARCHIVO: '1.3.6.1.4.1.57153.1.1.1.1',
  OID_TIPO_PERSONA_NATURAL_DSCF: '1.3.6.1.4.1.57153.1.1.1.2',
  OID_TIPO_MIEMBRO_EMPRESA_ARCHIVO: '1.3.6.1.4.1.57153.1.1.2.1',
  OID_TIPO_MIEMBRO_EMPRESA_DSCF: '1.3.6.1.4.1.57153.1.1.2.2',
  OID_TIPO_REPRESENTANTE_LEGAL_ARCHIVO: '1.3.6.1.4.1.57153.1.1.3.1',
  OID_TIPO_REPRESENTANTE_LEGAL_DSCF: '1.3.6.1.4.1.57153.1.1.3.2',
  OID_TIPO_PERSONA_JURIDICA_ARCHIVO: '1.3.6.1.4.1.57153.1.1.4.1',
  OID_TIPO_PERSONA_JURIDICA_DSCF: '1.3.6.1.4.1.57153.1.1.4.2',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.57153.1.1.5.2',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.57153.102.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.57153.102.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.57153.102.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.57153.102.3.4',
  OID_CARGO: '1.3.6.1.4.1.57153.102.3.5',
  OID_DIRECCION: '1.3.6.1.4.1.57153.102.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.57153.102.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.57153.102.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.57153.102.3.10',
  OID_RUC: '1.3.6.1.4.1.57153.102.3.11',
  OID_PAIS: '1.3.6.1.4.1.57153.102.3.12',
  OID_CERTIFICADO: '1.3.6.1.4.1.57153.102.3.50',
  OID_CONTENEDOR: '1.3.6.1.4.1.57153.102.3.51',
  OID_RUP: '1.3.6.1.4.1.57153.102.3.52',
} as const;

// ------------------------------------------------------------------ ext

/** Port of `CertificadoExtImplEcplipsoft` (sic): data read from subjectAltName otherNames. */
export class CertificadoExtImplEcplipsoft extends Certificado {
  readonly tipos = tipos();

  getCedulaPasaporte(): string {
    return this.getSubjectAlternativeName(Ext.OID_CEDULA_PASAPORTE);
  }

  getNombres(): string {
    return this.getSubjectAlternativeName(Ext.OID_NOMBRES);
  }

  getPrimerApellido(): string {
    return this.getSubjectAlternativeName(Ext.OID_APELLIDO_1);
  }

  getSegundoApellido(): string {
    return this.getSubjectAlternativeName(Ext.OID_APELLIDO_2);
  }

  getDireccion(): string {
    return this.getSubjectAlternativeName(Ext.OID_DIRECCION);
  }

  getTelefono(): string {
    return this.getSubjectAlternativeName(Ext.OID_TELEFONO);
  }

  getCiudad(): string {
    return this.getSubjectAlternativeName(Ext.OID_CIUDAD);
  }

  getPais(): string {
    return this.getSubjectAlternativeName(Ext.OID_PAIS);
  }

  getRuc(): string {
    return this.getSubjectAlternativeName(Ext.OID_RUC);
  }
}

export class CertificadoExtPersonalNaturalEclipsoft extends CertificadoExtImplEcplipsoft {
  override readonly tipos = tipos('PersonaNatural');
}

/** Java: implements CertificadoPersonaJuridica (not CertificadoMiembroEmpresa). */
export class CertificadoExtMiembroEmpresaEclipsoft extends CertificadoExtImplEcplipsoft {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtPersonaJuridicaPrivadaEclipsoft extends CertificadoExtImplEcplipsoft {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtRepresentanteLegalEclipsoft extends CertificadoExtImplEcplipsoft {
  override readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtSelladoTiempoEclipsoft extends CertificadoExtImplEcplipsoft {
  override readonly tipos = tipos('SelladoTiempo');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCommonName(): string {
    return '';
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryEclipsoft.getRootCertificate` (Uanataca sub CAs). */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertUanataca0120162029)) return SubCaCertUanataca0120162029;
  if (verifySignature(certificado, SubCaCertUanataca0220162029)) return SubCaCertUanataca0220162029;
  if (verifySignature(certificado, SubCaCertUanataca0320212034)) return SubCaCertUanataca0320212034;
  return null;
}

/** Port of `CertificadoDataFactoryEclipsoft.getDatosUsuarioEclipsoft`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplEcplipsoft) {
      if (c instanceof CertificadoExtPersonalNaturalEclipsoft) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtMiembroEmpresaEclipsoft) {
        datosUsuario.setTipoCertificado('Miembro Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtRepresentanteLegalEclipsoft) {
        datosUsuario.setTipoCertificado('Representante Legal (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtPersonaJuridicaPrivadaEclipsoft) {
        datosUsuario.setTipoCertificado('Persona Jurídica Privada (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        // Java quirk: the values are copied from datosUsuario itself
        datosUsuario.setRuc(datosUsuario.ruc);
        datosUsuario.setRazonSocial(datosUsuario.getRazonSocial());
        datosUsuario.setCargo(datosUsuario.cargo);
      }
      if (c instanceof CertificadoExtSelladoTiempoEclipsoft) {
        datosUsuario.setTipoCertificado('Sellado de Tiempo (EXT)');
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCommonName(c.getCommonName());
      }
    }
    // RESOLUCION-ARCOTEL-2024-0176: subject based certificates commented out in Java
    datosUsuario.setCertificadoDigitalValido(true);
  }
  return datosUsuario;
}

function construir(certificado: Certificate): Certificado | null {
  if (hasCertificatePoliciesMatchingPattern(certificado, '1.3.6.1.4.1.57153.1.1', '')) {
    if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_ARCHIVO)) {
      return new CertificadoExtPersonalNaturalEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_DSCF)) {
      return new CertificadoExtPersonalNaturalEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_ARCHIVO)) {
      return new CertificadoExtMiembroEmpresaEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_DSCF)) {
      return new CertificadoExtMiembroEmpresaEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL_ARCHIVO)) {
      return new CertificadoExtRepresentanteLegalEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL_DSCF)) {
      return new CertificadoExtRepresentanteLegalEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_ARCHIVO)) {
      return new CertificadoExtPersonaJuridicaPrivadaEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_DSCF)) {
      return new CertificadoExtPersonaJuridicaPrivadaEclipsoft(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
      return new CertificadoExtSelladoTiempoEclipsoft(certificado);
    }
  }
  return null;
}
