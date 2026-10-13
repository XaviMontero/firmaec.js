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
  SubCa1CertCorpNewBest20232033,
  SubCa1CertCorpNewBest2026022620400223,
  SubCa2CertCorpNewBest20232033,
  SubCa2CertCorpNewBest2026022620400223,
  SubCa3CertCorpNewBest20232033,
  SubCa3CertCorpNewBest2026022620400223,
} from './certs.js';

/** Port of `CertificadoCorpNewBest` (OIDs). */
export const Subj = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.64849.2.1.1',
  OID_TIPO_PERSONA_NATURAL_DSCF: '1.3.6.1.4.1.64849.2.1.2',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.64849.2.2.1',
  OID_TIPO_MIEMBRO_EMPRESA_DSCF: '1.3.6.1.4.1.64849.2.2.2',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.64849.2.3.1',
  OID_TIPO_REPRESENTANTE_LEGAL_DSCF: '1.3.6.1.4.1.64849.2.3.2',
  OID_TIPO_SELLO_ELECTRONICO: '1.3.6.1.4.1.64849.102.2.4.1',
  OID_TIPO_SELLO_ELECTRONICO_DSCF: '1.3.6.1.4.1.64849.102.2.4.2',
  OID_TIPO_SELLO_TIEMPO: '1.3.6.1.4.1.64849.102.2.5.1',
} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.34380.2.7',
  OID_TIPO_PERSONA_JURIDICA: '1.3.6.1.4.1.34380.2.8',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.34380.2.10',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.34380.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.34380.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.34380.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.34380.3.4',
  OID_CARGO: '1.3.6.1.4.1.34380.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.34380.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.34380.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.34380.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.34380.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.34380.3.10',
  OID_RUC: '1.3.6.1.4.1.34380.3.11',
  OID_PAIS: '1.3.6.1.4.1.34380.3.12',
} as const;

// ------------------------------------------------------------------ ext

export class CertificadoExtImplCorpNewBest extends Certificado {
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

export class CertificadoExtPersonaNaturalCorpNewBest extends CertificadoExtImplCorpNewBest {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtPersonaJuridicaCorpNewBest extends CertificadoExtImplCorpNewBest {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

export class CertificadoExtMiembroEmpresaCorpNewBest extends CertificadoExtImplCorpNewBest {
  override readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalCorpNewBest extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaCorpNewBest extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

/** Java: implements CertificadoRepresentanteLegal (sic). Not used by the factory. */
export class CertificadoSubjPersonaJuridicaCorpNewBest extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjRepresentanteLegalCorpNewBest extends CertificadoSubjImpl {
  readonly tipos = tipos('RepresentanteLegal');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelloElectronicoCorpNewBest extends CertificadoSubjImpl {
  readonly tipos = tipos('SelloElectronico');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

export class CertificadoSubjSelladoTiempoCorpNewBest extends CertificadoSubjImpl {
  readonly tipos = tipos('SelladoTiempo');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryCorpNewBest.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCa1CertCorpNewBest20232033)) return SubCa1CertCorpNewBest20232033;
  if (verifySignature(certificado, SubCa2CertCorpNewBest20232033)) return SubCa2CertCorpNewBest20232033;
  if (verifySignature(certificado, SubCa3CertCorpNewBest20232033)) return SubCa3CertCorpNewBest20232033;
  if (verifySignature(certificado, SubCa1CertCorpNewBest2026022620400223)) return SubCa1CertCorpNewBest2026022620400223;
  if (verifySignature(certificado, SubCa2CertCorpNewBest2026022620400223)) return SubCa2CertCorpNewBest2026022620400223;
  if (verifySignature(certificado, SubCa3CertCorpNewBest2026022620400223)) return SubCa3CertCorpNewBest2026022620400223;
  return null;
}

/** Port of `CertificadoDataFactoryCorpNewBest.getDatosUsuarioCorpNewBest`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplCorpNewBest) {
      if (c instanceof CertificadoExtPersonaNaturalCorpNewBest) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (c instanceof CertificadoExtPersonaJuridicaCorpNewBest) {
        datosUsuario.setTipoCertificado('Persona Jurídica (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (c instanceof CertificadoExtMiembroEmpresaCorpNewBest) {
        datosUsuario.setTipoCertificado('Miembro Empresa (EXT)');
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
  if (hasExtensionMatchingPattern(certificado, '1.3.6.1.4.1', '34380.3.1')) {
    if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoExtPersonaNaturalCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
      return new CertificadoExtPersonaJuridicaCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_MIEMBRO_EMPRESA)) {
      return new CertificadoExtMiembroEmpresaCorpNewBest(certificado);
    }
  } else {
    // RESOLUCION-ARCOTEL-2024-0176
    if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
      return new CertificadoSubjPersonaNaturalCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL_DSCF)) {
      return new CertificadoSubjPersonaNaturalCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
      return new CertificadoSubjMiembroEmpresaCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA_DSCF)) {
      return new CertificadoSubjMiembroEmpresaCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
      return new CertificadoSubjRepresentanteLegalCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL_DSCF)) {
      return new CertificadoSubjRepresentanteLegalCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)) {
      return new CertificadoSubjSelloElectronicoCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO_DSCF)) {
      return new CertificadoSubjSelloElectronicoCorpNewBest(certificado);
    } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_TIEMPO)) {
      return new CertificadoSubjSelladoTiempoCorpNewBest(certificado);
    }
  }
  return null;
}
