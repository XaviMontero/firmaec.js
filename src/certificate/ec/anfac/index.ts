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
import { certificateHasPolicy, hasExtensionMatchingPattern, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import {
  CaCertAnfAc20242044_37442,
  SubCaAnfAc20252044_37442,
  SubCaAnfAc20262044_37442,
  SubCaCertAnfAc20162032_18332,
  SubCaCertAnfAc20192029_37442,
} from './certs.js';

/** Port of `CertificadoAnfAc` (OIDs). */
export const Subj = {
  OID_CERTIFICADO_PERSONA_NATURAL: '1.3.6.1.4.1.37442.2.1.1',
  OID_CERTIFICADO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.37442.2.2.1',
  OID_CERTIFICADO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.37442.2.3.1',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.37442.102.2.5.1',
  OID_SELLO_ELECTRONICO: '1.3.6.1.4.1.37442.102.2.4.1',
} as const;

export const Ext18332 = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.18332.3.4.1.2.22',
  OID_TIPO_PERSONA_JURIDICA: '1.3.6.1.4.1.18332.2.5.1.3',
  OID_TIPO_FUNCIONARIO_PUBLICO: '1.3.6.1.4.1.18332.4.1.3.22',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.18332.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.18332.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.18332.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.18332.3.4',
  OID_CARGO: '1.3.6.1.4.1.18332.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.18332.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.18332.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.18332.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.18332.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.18332.3.10',
  OID_RUC: '1.3.6.1.4.1.18332.3.11',
  OID_PAIS: '1.3.6.1.4.1.18332.3.12',
  OID_CONTENEDOR: '1.3.6.1.4.1.18332.19',
} as const;

export const Ext37442 = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.37442.3.4.1.2.22',
  OID_TIPO_PERSONA_NATURAL_TOKEN: '1.3.6.1.4.1.37442.3.4.1.4.22',
  OID_TIPO_PERSONA_JURIDICA: '1.3.6.1.4.1.37442.2.5.1.3',
  OID_TIPO_PERSONA_JURIDICA_TOKEN: '1.3.6.1.4.1.37442.2.5.1.10',
  OID_TIPO_FUNCIONARIO_PUBLICO: '1.3.6.1.4.1.37442.4.1.3.22',
  // Java: same value as OID_TIPO_FUNCIONARIO_PUBLICO
  OID_TIPO_FUNCIONARIO_PUBLICO_TOKEN: '1.3.6.1.4.1.37442.4.1.3.22',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.37442.102.2.5.1',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.37442.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.37442.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.37442.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.37442.3.4',
  OID_CARGO: '1.3.6.1.4.1.37442.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.37442.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.37442.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.37442.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.37442.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.37442.3.10',
  OID_RUC: '1.3.6.1.4.1.37442.3.11',
  OID_PAIS: '1.3.6.1.4.1.37442.3.12',
  OID_CONTENEDOR: '1.3.6.1.4.1.37442.19',
} as const;

// ------------------------------------------------------------- ext 18332

export class CertificadoExtImplAnfAc_18332 extends Certificado {
  readonly tipos = tipos();

  getCedulaPasaporte(): string {
    return this.getExtensionField(Ext18332.OID_CEDULA_PASAPORTE);
  }

  getNombres(): string {
    return this.getExtensionField(Ext18332.OID_NOMBRES);
  }

  getPrimerApellido(): string {
    return this.getExtensionField(Ext18332.OID_APELLIDO_1);
  }

  getSegundoApellido(): string {
    return this.getExtensionField(Ext18332.OID_APELLIDO_2);
  }

  getDireccion(): string {
    return this.getExtensionField(Ext18332.OID_DIRECCION);
  }

  getTelefono(): string {
    return this.getExtensionField(Ext18332.OID_TELEFONO);
  }

  getCiudad(): string {
    return this.getExtensionField(Ext18332.OID_CIUDAD);
  }

  getPais(): string {
    return this.getExtensionField(Ext18332.OID_PAIS);
  }

  getRuc(): string {
    return this.getExtensionField(Ext18332.OID_RUC);
  }
}

export class CertificadoExtPersonaNaturalAnfAc_18332 extends CertificadoExtImplAnfAc_18332 {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtFuncionarioPublicoAnfAc_18332 extends CertificadoExtImplAnfAc_18332 {
  override readonly tipos = tipos('FuncionarioPublico');

  getRazonSocial(): string {
    return this.getExtensionField(Ext18332.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext18332.OID_CARGO);
  }

  getInstitucion(): string {
    return this.getExtensionField(Ext18332.OID_INSTITUCION);
  }
}

export class CertificadoExtPersonaJuridicaAnfAc_18332 extends CertificadoExtImplAnfAc_18332 {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getExtensionField(Ext18332.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext18332.OID_CARGO);
  }
}

// ------------------------------------------------------------- ext 37442

export class CertificadoExtImplAnfAc_37442 extends Certificado {
  readonly tipos = tipos();

  getCedulaPasaporte(): string {
    return this.getExtensionField(Ext37442.OID_CEDULA_PASAPORTE);
  }

  getNombres(): string {
    return this.getExtensionField(Ext37442.OID_NOMBRES);
  }

  getPrimerApellido(): string {
    return this.getExtensionField(Ext37442.OID_APELLIDO_1);
  }

  getSegundoApellido(): string {
    return this.getExtensionField(Ext37442.OID_APELLIDO_2);
  }

  getDireccion(): string {
    return this.getExtensionField(Ext37442.OID_DIRECCION);
  }

  getTelefono(): string {
    return this.getExtensionField(Ext37442.OID_TELEFONO);
  }

  getCiudad(): string {
    return this.getExtensionField(Ext37442.OID_CIUDAD);
  }

  getPais(): string {
    return this.getExtensionField(Ext37442.OID_PAIS);
  }

  getRuc(): string {
    return this.getExtensionField(Ext37442.OID_RUC);
  }
}

export class CertificadoExtPersonaNaturalAnfAc_37442 extends CertificadoExtImplAnfAc_37442 {
  override readonly tipos = tipos('PersonaNatural');
}

/**
 * Java quirk kept on purpose: this class statically imports `Ext18332.*`, so
 * razón social, cargo and institución are read from the 18332 OIDs.
 */
export class CertificadoExtFuncionarioPublicoAnfAc_37442 extends CertificadoExtImplAnfAc_37442 {
  override readonly tipos = tipos('FuncionarioPublico');

  getRazonSocial(): string {
    return this.getExtensionField(Ext18332.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext18332.OID_CARGO);
  }

  getInstitucion(): string {
    return this.getExtensionField(Ext18332.OID_INSTITUCION);
  }
}

export class CertificadoExtPersonaJuridicaAnfAc_37442 extends CertificadoExtImplAnfAc_37442 {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getExtensionField(Ext37442.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext37442.OID_CARGO);
  }
}

export class CertificadoExtSelladoTiempoAnfAc_37442 extends CertificadoExtImplAnfAc_37442 {
  override readonly tipos = tipos('SelladoTiempo');

  getRazonSocial(): string {
    return this.getExtensionField(Ext37442.OID_RAZON_SOCIAL);
  }

  getCommonName(): string {
    return '';
  }
}

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalAnfAc extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaAnfAc extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalAnfAc extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelladoTiempoAnfAc extends CertificadoSubjImpl {
  readonly tipos = tipos('SelladoTiempo');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

export class CertificadoSubjSelloElectronicoAnfAc extends CertificadoSubjImpl {
  readonly tipos = tipos('SelloElectronico');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryAnfAc.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  // Certificado firmado por la raíz (p. ej. el intermedio 2025-2044)
  if (verifySignature(certificado, CaCertAnfAc20242044_37442)) return CaCertAnfAc20242044_37442;
  if (verifySignature(certificado, SubCaCertAnfAc20162032_18332)) return SubCaCertAnfAc20162032_18332;
  if (verifySignature(certificado, SubCaCertAnfAc20192029_37442)) return SubCaCertAnfAc20192029_37442;
  if (verifySignature(certificado, SubCaAnfAc20252044_37442)) return SubCaAnfAc20252044_37442;
  if (verifySignature(certificado, SubCaAnfAc20262044_37442)) return SubCaAnfAc20262044_37442;
  return null;
}

/** Port of `CertificadoDataFactoryAnfAc.getDatosUsuarioAnfAc`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c18332 = construir18332(certificado);
  if (c18332 !== null) {
    datosUsuario = new DatosUsuario();
    if (c18332 instanceof CertificadoExtImplAnfAc_18332) {
      if (c18332 instanceof CertificadoExtPersonaNaturalAnfAc_18332) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c18332.getCedulaPasaporte());
        datosUsuario.setNombre(c18332.getNombres());
        datosUsuario.setApellido(c18332.getPrimerApellido() + ' ' + c18332.getSegundoApellido());
      }
      if (c18332 instanceof CertificadoExtFuncionarioPublicoAnfAc_18332) {
        datosUsuario.setTipoCertificado('Funcionario Público (EXT)');
        datosUsuario.setCedula(c18332.getCedulaPasaporte());
        datosUsuario.setNombre(c18332.getNombres());
        datosUsuario.setApellido(c18332.getPrimerApellido() + ' ' + c18332.getSegundoApellido());
        datosUsuario.setRuc(c18332.getRuc());
        datosUsuario.setInstitucion(c18332.getInstitucion());
        datosUsuario.setCargo(c18332.getCargo());
      }
      if (c18332 instanceof CertificadoExtPersonaJuridicaAnfAc_18332) {
        datosUsuario.setTipoCertificado('Persona Jurídica (EXT)');
        datosUsuario.setCedula(c18332.getCedulaPasaporte());
        datosUsuario.setNombre(c18332.getNombres());
        datosUsuario.setApellido(c18332.getPrimerApellido() + ' ' + c18332.getSegundoApellido());
        datosUsuario.setRuc(c18332.getRuc());
        datosUsuario.setRazonSocial(c18332.getRazonSocial());
        datosUsuario.setCargo(c18332.getCargo());
      }
    }
    datosUsuario.setCertificadoDigitalValido(true);
  }
  const c = construir37442(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplAnfAc_37442) {
      if (c instanceof CertificadoExtPersonaNaturalAnfAc_37442) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtFuncionarioPublicoAnfAc_37442) {
        datosUsuario.setTipoCertificado('Funcionario Público (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setInstitucion(c.getInstitucion());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtPersonaJuridicaAnfAc_37442) {
        datosUsuario.setTipoCertificado('Persona Jurídica (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtSelladoTiempoAnfAc_37442) {
        datosUsuario.setTipoCertificado('Sellado de Tiempo (EXT)');
        datosUsuario.setCommonName(c.getCommonName());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
      }
    }
    // RESOLUCION-ARCOTEL-2024-0176
    if (c instanceof CertificadoSubjImpl) {
      // Java: instanceof over the marker interfaces (which inherit from CertificadoPersonaNatural)
      if (esPersonaNatural(c)) {
        datosUsuario.setTipoCertificado('Persona Natural');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
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

function construir18332(certificado: Certificate): Certificado | null {
  if (hasExtensionMatchingPattern(certificado, '1.3.6.1.4.1', '3.1')) {
    if (certificateHasPolicy(certificado, Ext18332.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoExtPersonaNaturalAnfAc_18332(certificado);
    } else if (certificateHasPolicy(certificado, Ext18332.OID_TIPO_PERSONA_JURIDICA)) {
      return new CertificadoExtPersonaJuridicaAnfAc_18332(certificado);
    } else if (certificateHasPolicy(certificado, Ext18332.OID_TIPO_FUNCIONARIO_PUBLICO)) {
      return new CertificadoExtFuncionarioPublicoAnfAc_18332(certificado);
    }
  }
  return null;
}

function construir37442(certificado: Certificate): Certificado | null {
  if (hasExtensionMatchingPattern(certificado, '1.3.6.1.4.1', '3.1')) {
    if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoExtPersonaNaturalAnfAc_37442(certificado);
    } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_NATURAL_TOKEN)) {
      return new CertificadoExtPersonaNaturalAnfAc_37442(certificado);
    } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_JURIDICA)) {
      return new CertificadoExtPersonaJuridicaAnfAc_37442(certificado);
    } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_PERSONA_JURIDICA_TOKEN)) {
      return new CertificadoExtPersonaJuridicaAnfAc_37442(certificado);
    } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_FUNCIONARIO_PUBLICO)) {
      return new CertificadoExtFuncionarioPublicoAnfAc_37442(certificado);
    } else if (certificateHasPolicy(certificado, Ext37442.OID_TIPO_FUNCIONARIO_PUBLICO_TOKEN)) {
      return new CertificadoExtFuncionarioPublicoAnfAc_37442(certificado);
    } else if (certificateHasPolicy(certificado, Ext37442.OID_SELLADO_TIEMPO)) {
      return new CertificadoExtSelladoTiempoAnfAc_37442(certificado);
    }
  } else {
    // RESOLUCION-ARCOTEL-2024-0176
    if (certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL)) {
      return new CertificadoSubjPersonaNaturalAnfAc(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA)) {
      return new CertificadoSubjMiembroEmpresaAnfAc(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL)) {
      return new CertificadoSubjRepresentanteLegalAnfAc(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_SELLADO_TIEMPO)) {
      return new CertificadoSubjSelladoTiempoAnfAc(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_SELLO_ELECTRONICO)) {
      return new CertificadoSubjSelloElectronicoAnfAc(certificado);
    }
  }
  return null;
}
