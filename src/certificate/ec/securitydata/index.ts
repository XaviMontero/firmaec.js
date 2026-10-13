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
  esSelladoTiempo,
  esSelloElectronico,
  tipos,
} from '../../base.js';
import { certificateHasPolicy, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import { SubCaCertSecurityData20112026, SubCaCertSecurityData20192031, SubCaCertSecurityData20202039 } from './certs.js';

/** Port of `CertificadoSecurityData` (OIDs). */
export const Subj = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.37746.2.1.1',
  OID_TIPO_PERSONA_NATURAL_DSCF: '1.3.6.1.4.1.37746.2.1.2',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.37746.2.2.1',
  OID_TIPO_MIEMBRO_EMPRESA_DSCF: '1.3.6.1.4.1.37746.2.2.2',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.37746.2.3.1',
  OID_TIPO_REPRESENTANTE_LEGAL_DSCF: '1.3.6.1.4.1.37746.2.3.2',
  OID_TIPO_SELLO_ELECTRONICO: '1.3.6.1.4.1.37746.102.2.4.1',
  OID_TIPO_SELLO_ELECTRONICO_DSCF: '1.3.6.1.4.1.37746.102.2.4.2',
  OID_TIPO_SELLO_TIEMPO_DSCF: '1.3.6.1.4.1.37746.102.2.5.1',
} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.37746.2.7',
  OID_TIPO_PERSONA_JURIDICA_EMPRESA: '1.3.6.1.4.1.37746.2.8',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.37746.2.9',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.37746.2.10',
  OID_TIPO_FUNCIONARIO_PUBLICO: '1.3.6.1.4.1.37746.2.11',
  OID_TIPO_PERSONA_NATURAL_PROFESIONAL: '1.3.6.1.4.1.37746.2.15',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.37746.3.28',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.37746.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.37746.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.37746.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.37746.3.4',
  OID_CARGO: '1.3.6.1.4.1.37746.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.37746.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.37746.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.37746.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.37746.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.37746.3.10',
  OID_RUC: '1.3.6.1.4.1.37746.3.11',
  OID_PAIS: '1.3.6.1.4.1.37746.3.12',
  OID_NOMBRE_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.37746.3.26',
  OID_RUP: '1.3.6.1.4.1.37746.3.29',
  OID_PROFESION: '1.3.6.1.4.1.37746.3.30',
  OID_NUMERO_FACTURA: '1.3.6.1.4.1.37746.3.32',
  OID_NUMERO_SERIE_TOKEN: '1.3.6.1.4.1.37746.3.33',
} as const;

// ------------------------------------------------------------------ ext

export class CertificadoExtImplSecurityData extends Certificado {
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

export class CertificadoExtPersonaNaturalSecurityData extends CertificadoExtImplSecurityData {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtFuncionarioPublicoSecurityData extends CertificadoExtImplSecurityData {
  override readonly tipos = tipos('FuncionarioPublico');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }

  getInstitucion(): string {
    return this.getExtensionField(Ext.OID_INSTITUCION);
  }
}

export class CertificadoExtMiembroEmpresaSecurityData extends CertificadoExtImplSecurityData {
  override readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

export class CertificadoExtRepresentanteLegalSecurityData extends CertificadoExtImplSecurityData {
  override readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

export class CertificadoExtPersonaJuridicaSecurityData extends CertificadoExtImplSecurityData {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

export class CertificadoExtSelladoTiempoSecurityData extends CertificadoExtImplSecurityData {
  override readonly tipos = tipos('SelladoTiempo');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCommonName(): string {
    return '';
  }
}

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalSecurityData extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaSecurityData extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalSecurityData extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelloElectronicoSecurityData extends CertificadoSubjImpl {
  readonly tipos = tipos('SelloElectronico');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

export class CertificadoSubjSelladoTiempoSecurityData extends CertificadoSubjImpl {
  readonly tipos = tipos('SelladoTiempo');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactorySecurityData.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertSecurityData20112026)) return SubCaCertSecurityData20112026;
  if (verifySignature(certificado, SubCaCertSecurityData20192031)) return SubCaCertSecurityData20192031;
  if (verifySignature(certificado, SubCaCertSecurityData20202039)) return SubCaCertSecurityData20202039;
  return null;
}

/** Port of `CertificadoDataFactorySecurityData.getDatosUsuarioSecurityData`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplSecurityData) {
      if (c instanceof CertificadoExtPersonaNaturalSecurityData) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtFuncionarioPublicoSecurityData) {
        datosUsuario.setTipoCertificado('Funcionario Público (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setInstitucion(c.getInstitucion());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtMiembroEmpresaSecurityData) {
        datosUsuario.setTipoCertificado('Miembro de Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtRepresentanteLegalSecurityData) {
        datosUsuario.setTipoCertificado('Representante Legal (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtPersonaJuridicaSecurityData) {
        datosUsuario.setTipoCertificado('Persona Jurídica (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtSelladoTiempoSecurityData) {
        datosUsuario.setTipoCertificado('Sellado de Tiempo (EXT)');
        datosUsuario.setCedula('');
        datosUsuario.setNombre('');
        datosUsuario.setApellido('');
        datosUsuario.setCommonName('');
        datosUsuario.setRuc('');
        datosUsuario.setRazonSocial('');
      }
    }
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
        datosUsuario.setTipoCertificado('Sellado Electrónico');
        datosUsuario.setCommonName(c.getCommonName());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
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
  if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
    return new CertificadoExtPersonaNaturalSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA_EMPRESA)) {
    return new CertificadoExtPersonaJuridicaSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_REPRESENTANTE_LEGAL)) {
    return new CertificadoExtRepresentanteLegalSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
    return new CertificadoExtMiembroEmpresaSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_FUNCIONARIO_PUBLICO)) {
    return new CertificadoExtFuncionarioPublicoSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL_PROFESIONAL)) {
    return new CertificadoExtPersonaNaturalSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
    return new CertificadoExtSelladoTiempoSecurityData(certificado);
  }
  // RESOLUCION-ARCOTEL-2024-0176
  else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
    return new CertificadoSubjPersonaNaturalSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL_DSCF)) {
    return new CertificadoSubjPersonaNaturalSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
    return new CertificadoSubjRepresentanteLegalSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL_DSCF)) {
    return new CertificadoSubjRepresentanteLegalSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
    return new CertificadoSubjMiembroEmpresaSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA_DSCF)) {
    return new CertificadoSubjMiembroEmpresaSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)) {
    return new CertificadoSubjSelloElectronicoSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO_DSCF)) {
    return new CertificadoSubjSelloElectronicoSecurityData(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_TIEMPO_DSCF)) {
    return new CertificadoSubjSelladoTiempoSecurityData(certificado);
  }
  return null;
}
