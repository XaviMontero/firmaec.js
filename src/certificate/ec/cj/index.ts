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
import { SubCaCertConsejoJudicatura } from './certs.js';

/** Port of `CertificadoConsejoJudicatura` (OIDs). `Subj` is empty (commented out in Java). */
export const Subj = {} as const;

export const Ext = {
  // OIDs de tipo de certificado:
  OID_TIPO_PERSONA_NATURAL_HW_TOKEN: '1.3.6.1.4.1.43745.1.2.1.1.1.1',
  OID_TIPO_PERSONA_NATURAL_HW_HSM_SFC: '1.3.6.1.4.1.43745.1.2.1.1.1.2',
  OID_TIPO_PERSONA_NATURAL_HW_HSM: '1.3.6.1.4.1.43745.1.2.1.1.1.3',
  OID_TIPO_PERSONA_NATURAL_SW_PKCS12: '1.3.6.1.4.1.43745.1.2.1.1.2.1',
  OID_TIPO_PERSONA_JURIDICA_PRIVADA_HW_TOKEN: '1.3.6.1.4.1.43745.1.2.1.2.1.1',
  OID_TIPO_PERSONA_JURIDICA_PRIVADA_HW_HSM_SFC: '1.3.6.1.4.1.43745.1.2.1.2.1.2',
  OID_TIPO_PERSONA_JURIDICA_PRIVADA_SW_PKCS12: '1.3.6.1.4.1.43745.1.2.1.2.2.1',
  OID_TIPO_PERSONA_JURIDICA_PUBLICA_HW_TOKEN: '1.3.6.1.4.1.43745.1.2.1.3.1.1',
  OID_TIPO_PERSONA_JURIDICA_PUBLICA_HW_HSM_SFC: '1.3.6.1.4.1.43745.1.2.1.3.1.2',
  OID_TIPO_PERSONA_JURIDICA_PUBLICA_HW_HSM: '1.3.6.1.4.1.43745.1.2.1.3.1.3',
  OID_TIPO_PERSONA_JURIDICA_PUBLICA_SW_PKCS12: '1.3.6.1.4.1.43745.1.2.1.3.2.1',
  OID_TIPO_MIEMBRO_EMPRESA_HW_TOKEN: '1.3.6.1.4.1.43745.1.2.1.4.1.1',
  OID_TIPO_MIEMBRO_EMPRESA_HW_HSM_SFC: '1.3.6.1.4.1.43745.1.2.1.4.1.2',
  OID_TIPO_MIEMBRO_EMPRESA_HW_HSM: '1.3.6.1.4.1.43745.1.2.1.4.1.3',
  OID_TIPO_MIEMBRO_EMPRESA_SW_PKCS12: '1.3.6.1.4.1.43745.1.2.1.4.2.1',
  OID_TIPO_EMPRESA_HW_HSM_SFC: '1.3.6.1.4.1.43745.1.2.2.1.1.2',
  OID_TIPO_EMPRESA_HW_HSM: '1.3.6.1.4.1.43745.1.2.2.1.2.1',
  OID_TIPO_DEPARTAMENTO_EMPRESA_HW_HSM_SFC: '1.3.6.1.4.1.43745.1.2.3.1.1.2',
  OID_TIPO_DEPARTAMENTO_EMPRESA_SW_PKCS12: '1.3.6.1.4.1.43745.1.2.3.1.2.1',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.43745.1.2.4.1.1.3',
  // OIDs de Campos del Certificado:
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.43745.1.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.43745.1.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.43745.1.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.43745.1.3.4',
  OID_CARGO: '1.3.6.1.4.1.43745.1.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.43745.1.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.43745.1.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.43745.1.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.43745.1.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.43745.1.3.10',
  OID_RUC: '1.3.6.1.4.1.43745.1.3.11',
  OID_PAIS: '1.3.6.1.4.1.43745.1.3.12',
  OID_CERTIFICADO: '1.3.6.1.4.1.43745.1.3.50',
  OID_CONTENEDOR: '1.3.6.1.4.1.43745.1.3.51',
  OID_RUP: '1.3.6.1.4.1.43745.1.3.52',
  OID_PROFESION: '1.3.6.1.4.1.43745.1.3.53',
  OID_DEPARTAMENTO: '1.3.6.1.4.1.43745.1.3.54',
} as const;

// ------------------------------------------------------------------ ext

/** Data read from subjectAltName otherNames. */
export class CertificadoExtImplConsejoJudicatura extends Certificado {
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

export class CertificadoExtPersonaNaturalConsejoJudicatura extends CertificadoExtImplConsejoJudicatura {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtDepartamentoEmpresaConsejoJudicatura extends CertificadoExtImplConsejoJudicatura {
  override readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtEmpresaConsejoJudicatura extends CertificadoExtImplConsejoJudicatura {
  override readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtMiembroEmpresaConsejoJudicatura extends CertificadoExtImplConsejoJudicatura {
  override readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtPersonaJuridicaPrivadaConsejoJudicatura extends CertificadoExtImplConsejoJudicatura {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtPersonaJuridicaPublicaConsejoJudicatura extends CertificadoExtImplConsejoJudicatura {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtSelladoTiempoConsejoJudicatura extends CertificadoExtImplConsejoJudicatura {
  override readonly tipos = tipos('SelladoTiempo');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCommonName(): string {
    return '';
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryConsejoJudicatura.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertConsejoJudicatura)) return SubCaCertConsejoJudicatura;
  return null;
}

/** Port of `CertificadoDataFactoryConsejoJudicatura.getDatosUsuarioConsejoJudicatura`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplConsejoJudicatura) {
      if (c instanceof CertificadoExtPersonaNaturalConsejoJudicatura) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtDepartamentoEmpresaConsejoJudicatura) {
        datosUsuario.setTipoCertificado('Departamento Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtEmpresaConsejoJudicatura) {
        datosUsuario.setTipoCertificado('Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtMiembroEmpresaConsejoJudicatura) {
        datosUsuario.setTipoCertificado('Miembro de Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtPersonaJuridicaPrivadaConsejoJudicatura) {
        datosUsuario.setTipoCertificado('Persona Jurídica (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        // Java quirk: re-assigns the DatosUsuario's own (default) values instead of the certificate's
        datosUsuario.setRuc(datosUsuario.ruc);
        datosUsuario.setRazonSocial(datosUsuario.getRazonSocial());
        datosUsuario.setCargo(datosUsuario.cargo);
      }
      if (c instanceof CertificadoExtPersonaJuridicaPublicaConsejoJudicatura) {
        datosUsuario.setTipoCertificado('Persona Jurídica Pública (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtSelladoTiempoConsejoJudicatura) {
        datosUsuario.setTipoCertificado('Sellado de Tiempo (EXT)');
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
  if (hasCertificatePoliciesMatchingPattern(certificado, '1.3.6.1.4.1.43745.1.2', '')) {
    if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_HW_TOKEN)) {
      return new CertificadoExtPersonaNaturalConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_HW_HSM_SFC)) {
      return new CertificadoExtPersonaNaturalConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_HW_HSM)) {
      return new CertificadoExtPersonaNaturalConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_SW_PKCS12)) {
      return new CertificadoExtPersonaNaturalConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PRIVADA_HW_TOKEN)) {
      return new CertificadoExtPersonaJuridicaPrivadaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PRIVADA_HW_HSM_SFC)) {
      return new CertificadoExtPersonaJuridicaPrivadaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PRIVADA_SW_PKCS12)) {
      return new CertificadoExtPersonaJuridicaPrivadaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PUBLICA_HW_TOKEN)) {
      return new CertificadoExtPersonaJuridicaPublicaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PUBLICA_HW_HSM_SFC)) {
      return new CertificadoExtPersonaJuridicaPublicaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PUBLICA_HW_HSM)) {
      return new CertificadoExtPersonaJuridicaPublicaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_PUBLICA_SW_PKCS12)) {
      return new CertificadoExtPersonaJuridicaPublicaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_HW_TOKEN)) {
      return new CertificadoExtMiembroEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_HW_HSM_SFC)) {
      return new CertificadoExtMiembroEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_HW_HSM)) {
      return new CertificadoExtMiembroEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_SW_PKCS12)) {
      return new CertificadoExtMiembroEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_EMPRESA_HW_HSM_SFC)) {
      return new CertificadoExtEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_EMPRESA_HW_HSM)) {
      return new CertificadoExtEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_DEPARTAMENTO_EMPRESA_HW_HSM_SFC)) {
      return new CertificadoExtDepartamentoEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_DEPARTAMENTO_EMPRESA_SW_PKCS12)) {
      return new CertificadoExtDepartamentoEmpresaConsejoJudicatura(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
      return new CertificadoExtSelladoTiempoConsejoJudicatura(certificado);
    }
    // RESOLUCION-ARCOTEL-2024-0176 (commented out in Java)
  }
  return null;
}
