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
  esPersonaJuridica,
  esPersonaNatural,
  esRepresentanteLegal,
  esSelladoTiempo,
  tipos,
} from '../../base.js';
import { certificateHasPolicy, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import { SubCaCertUanataca0120162029, SubCaCertUanataca0220162029, SubCaCertUanataca0320212034 } from './certs.js';

/** Port of `CertificadoUanataca` (OIDs). */
export const Subj = {
  OID_TIPO_PERSONA_NATURAL_ARCHIVO: '1.3.6.1.4.1.65311.2.1.1',
  OID_TIPO_PERSONA_NATURAL_DSCF: '1.3.6.1.4.1.65311.2.1.2',
  OID_TIPO_MIEMBRO_EMPRESA_ARCHIVO: '1.3.6.1.4.1.65311.2.2.1',
  OID_TIPO_MIEMBRO_EMPRESA_DSCF: '1.3.6.1.4.1.65311.2.2.2',
  OID_TIPO_REPRESENTANTE_EMPRESA_ARCHIVO: '1.3.6.1.4.1.65311.2.3.1',
  OID_TIPO_REPRESENTANTE_EMPRESA_DSCF: '1.3.6.1.4.1.65311.2.3.2',
  OID_TIPO_PERSONA_JURIDICA_ARCHIVO: '1.3.6.1.4.1.65311.102.2.4.1',
  OID_TIPO_PERSONA_JURIDICA_DSCF: '1.3.6.1.4.1.65311.102.2.4.2',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.65311.102.2.5.1',
} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL_ARCHIVO: '1.3.6.1.4.1.47286.102.2.1.1',
  OID_TIPO_PERSONA_NATURAL_DSCF: '1.3.6.1.4.1.47286.102.2.1.2',
  OID_TIPO_MIEMBRO_EMPRESA_ARCHIVO: '1.3.6.1.4.1.47286.102.2.2.1',
  OID_TIPO_MIEMBRO_EMPRESA_DSCF: '1.3.6.1.4.1.47286.102.2.2.2',
  OID_TIPO_REPRESENTANTE_EMPRESA_ARCHIVO: '1.3.6.1.4.1.47286.102.2.3.1',
  OID_TIPO_REPRESENTANTE_EMPRESA_DSCF: '1.3.6.1.4.1.47286.102.2.3.2',
  OID_TIPO_PERSONA_JURIDICA_ARCHIVO: '1.3.6.1.4.1.47286.102.2.4.1',
  OID_TIPO_PERSONA_JURIDICA_DSCF: '1.3.6.1.4.1.47286.102.2.4.2',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.47286.102.2.5.1',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.47286.102.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.47286.102.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.47286.102.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.47286.102.3.4',
  OID_CARGO: '1.3.6.1.4.1.47286.102.3.5',
  OID_DIRECCION: '1.3.6.1.4.1.47286.102.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.47286.102.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.47286.102.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.47286.102.3.10',
  OID_RUC: '1.3.6.1.4.1.47286.102.3.11',
  OID_PAIS: '1.3.6.1.4.1.47286.102.3.12',
  OID_CERTIFICADO: '1.3.6.1.4.1.47286.102.3.50',
  OID_CONTENEDOR: '1.3.6.1.4.1.47286.102.3.51',
  OID_RUP: '1.3.6.1.4.1.47286.102.3.52',
  OID_PROFESION: '2.5.4.12',
  OID_DEPARTAMENTO: '2.5.4.11',
} as const;

// ------------------------------------------------------------------ ext

/** Port of `CertificadoExtImplUanataca`: data read from subjectAltName otherNames. */
export class CertificadoExtImplUanataca extends Certificado {
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

export class CertificadoExtPersonaNaturalUanataca extends CertificadoExtImplUanataca {
  override readonly tipos = tipos('PersonaNatural');
}

/** Java: implements CertificadoPersonaJuridica (not CertificadoMiembroEmpresa). */
export class CertificadoExtMiembroEmpresaUanataca extends CertificadoExtImplUanataca {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtPersonaJuridicaPrivadaUanataca extends CertificadoExtImplUanataca {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtRepresentanteLegalUanataca extends CertificadoExtImplUanataca {
  override readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getSubjectAlternativeName(Ext.OID_CARGO);
  }
}

export class CertificadoExtSelladoTiempoUanataca extends CertificadoExtImplUanataca {
  override readonly tipos = tipos('SelladoTiempo');

  getRazonSocial(): string {
    return this.getSubjectAlternativeName(Ext.OID_RAZON_SOCIAL);
  }

  getCommonName(): string {
    return '';
  }
}

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalUanataca extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjPersonaJuridicaUanataca extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjMiembroEmpresaUanataca extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalUanataca extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelladoTiempoUanataca extends CertificadoSubjImpl {
  readonly tipos = tipos('SelladoTiempo');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryUanataca.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertUanataca0120162029)) return SubCaCertUanataca0120162029;
  if (verifySignature(certificado, SubCaCertUanataca0220162029)) return SubCaCertUanataca0220162029;
  if (verifySignature(certificado, SubCaCertUanataca0320212034)) return SubCaCertUanataca0320212034;
  return null;
}

/** Port of `CertificadoDataFactoryUanataca.getDatosUsuarioUanataca`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplUanataca) {
      if (c instanceof CertificadoExtPersonaNaturalUanataca) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtMiembroEmpresaUanataca) {
        datosUsuario.setTipoCertificado('Miembro Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtPersonaJuridicaPrivadaUanataca) {
        datosUsuario.setTipoCertificado('Persona Jurídica Privada (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        // Java quirk: datosUsuario.setCargo(datosUsuario.getCargo())
        datosUsuario.setCargo(datosUsuario.cargo);
      }
      if (c instanceof CertificadoExtRepresentanteLegalUanataca) {
        datosUsuario.setTipoCertificado('Representante Legal (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtSelladoTiempoUanataca) {
        datosUsuario.setTipoCertificado('Sellado de Tiempo (EXT)');
        datosUsuario.setCommonName(c.getCommonName());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
      }
    }
    // RESOLUCION-ARCOTEL-2024-0176
    if (c instanceof CertificadoSubjImpl) {
      if (esPersonaNatural(c)) {
        datosUsuario.setTipoCertificado('Persona Natural');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido());
      }
      if (esPersonaJuridica(c)) {
        datosUsuario.setTipoCertificado('Persona Jurídica');
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
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
      if (esSelladoTiempo(c)) {
        datosUsuario.setTipoCertificado('Sellado de Tiempo');
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
  // No se implementa condicionamiento, debido que tienen OID's distintas
  if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_ARCHIVO)) {
    return new CertificadoExtPersonaNaturalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_DSCF)) {
    return new CertificadoExtPersonaNaturalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_ARCHIVO)) {
    return new CertificadoExtPersonaJuridicaPrivadaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_DSCF)) {
    return new CertificadoExtPersonaJuridicaPrivadaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_ARCHIVO)) {
    return new CertificadoExtMiembroEmpresaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA_DSCF)) {
    return new CertificadoExtMiembroEmpresaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_EMPRESA_ARCHIVO)) {
    return new CertificadoExtRepresentanteLegalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_EMPRESA_DSCF)) {
    return new CertificadoExtRepresentanteLegalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
    return new CertificadoExtSelladoTiempoUanataca(certificado);
  }
  // RESOLUCION-ARCOTEL-2024-0176
  else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL_ARCHIVO)) {
    return new CertificadoSubjPersonaNaturalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL_DSCF)) {
    return new CertificadoSubjPersonaNaturalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_JURIDICA_ARCHIVO)) {
    return new CertificadoSubjPersonaJuridicaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_JURIDICA_DSCF)) {
    return new CertificadoSubjPersonaJuridicaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA_ARCHIVO)) {
    return new CertificadoSubjMiembroEmpresaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA_DSCF)) {
    return new CertificadoSubjMiembroEmpresaUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_EMPRESA_ARCHIVO)) {
    return new CertificadoSubjRepresentanteLegalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_EMPRESA_DSCF)) {
    return new CertificadoSubjRepresentanteLegalUanataca(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_SELLADO_TIEMPO)) {
    return new CertificadoSubjSelladoTiempoUanataca(certificado);
  }
  return null;
}
