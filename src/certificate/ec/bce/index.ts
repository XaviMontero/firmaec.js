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
  esFuncionarioPublico,
  esMiembroEmpresa,
  esPersonaJuridica,
  esPersonaNatural,
  esRepresentanteLegal,
  esSelladoTiempo,
  tipos,
} from '../../base.js';
import { certificateHasPolicy, hasExtensionMatchingPattern, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { SubCaCertBce20112021, SubCaCertBce20192029 } from './certs.js';

/** Port of `CertificadoBancoCentral` (OIDs). `Subj` is empty in Java (commented out). */
export const Subj = {} as const;

export const Ext = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.37947.2.1.1',
  OID_TIPO_PERSONA_JURIDICA: '1.3.6.1.4.1.37947.2.2.1',
  OID_TIPO_FUNCIONARIO_PUBLICO: '1.3.6.1.4.1.37947.2.3.1',
  OID_SELLADO_TIEMPO: '1.3.6.1.4.1.37947.4.1',
  OID_CEDULA_PASAPORTE: '1.3.6.1.4.1.37947.3.1',
  OID_NOMBRES: '1.3.6.1.4.1.37947.3.2',
  OID_APELLIDO_1: '1.3.6.1.4.1.37947.3.3',
  OID_APELLIDO_2: '1.3.6.1.4.1.37947.3.4',
  OID_CARGO: '1.3.6.1.4.1.37947.3.5',
  OID_INSTITUCION: '1.3.6.1.4.1.37947.3.6',
  OID_DIRECCION: '1.3.6.1.4.1.37947.3.7',
  OID_TELEFONO: '1.3.6.1.4.1.37947.3.8',
  OID_CIUDAD: '1.3.6.1.4.1.37947.3.9',
  OID_RAZON_SOCIAL: '1.3.6.1.4.1.37947.3.10',
  OID_RUC: '1.3.6.1.4.1.37947.3.11',
  OID_CONTENEDOR: '1.3.6.1.4.1.37947.3.100',
  // BUG: En la documentacion del BCE no esta incluido?
  OID_PAIS: '1.3.6.1.4.1.37947.3.12',
} as const;

// ------------------------------------------------------------------ ext

export class CertificadoExtImplBancoCentral extends Certificado {
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

export class CertificadoExtPersonaNaturalBancoCentral extends CertificadoExtImplBancoCentral {
  override readonly tipos = tipos('PersonaNatural');
}

export class CertificadoExtFuncionarioPublicoBancoCentral extends CertificadoExtImplBancoCentral {
  override readonly tipos = tipos('FuncionarioPublico');

  getInstitucion(): string {
    return this.getExtensionField(Ext.OID_INSTITUCION);
  }

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

export class CertificadoExtPersonaJuridicaBancoCentral extends CertificadoExtImplBancoCentral {
  override readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCargo(): string {
    return this.getExtensionField(Ext.OID_CARGO);
  }
}

export class CertificadoExtSelladoTiempoBancoCentral extends CertificadoExtImplBancoCentral {
  override readonly tipos = tipos('SelladoTiempo');

  getRazonSocial(): string {
    return this.getExtensionField(Ext.OID_RAZON_SOCIAL);
  }

  getCommonName(): string {
    return '';
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryBancoCentral.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCaCertBce20112021)) return SubCaCertBce20112021;
  if (verifySignature(certificado, SubCaCertBce20192029)) return SubCaCertBce20192029;
  return null;
}

/** Port of `CertificadoDataFactoryBancoCentral.getDatosUsuarioBancoCentral`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
    if (c instanceof CertificadoExtImplBancoCentral) {
      // Java: instanceof over the marker interfaces (which inherit from CertificadoPersonaNatural)
      if (esPersonaNatural(c)) {
        datosUsuario.setTipoCertificado('Persona Natural (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
      }
      if (esFuncionarioPublico(c)) {
        datosUsuario.setTipoCertificado('Funcionario Publico (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setInstitucion(c.getInstitucion());
        datosUsuario.setCargo(c.getCargo());
      }
      if (esMiembroEmpresa(c)) {
        datosUsuario.setTipoCertificado('Miembro Empresa (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (esPersonaJuridica(c)) {
        datosUsuario.setTipoCertificado('Persona Jurídica (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (esRepresentanteLegal(c)) {
        datosUsuario.setTipoCertificado('Representante Legal (EXT)');
        datosUsuario.setCedula(c.getCedulaPasaporte());
        datosUsuario.setNombre(c.getNombres());
        datosUsuario.setApellido(c.getPrimerApellido() + ' ' + c.getSegundoApellido());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
        datosUsuario.setCargo(c.getCargo());
      }
      if (esSelladoTiempo(c)) {
        datosUsuario.setTipoCertificado('Sellado de Tiempo (EXT)');
        datosUsuario.setCommonName(c.getCommonName());
        datosUsuario.setRuc(c.getRuc());
        datosUsuario.setRazonSocial(c.getRazonSocial());
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
      return new CertificadoExtPersonaNaturalBancoCentral(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_PERSONA_JURIDICA)) {
      return new CertificadoExtPersonaJuridicaBancoCentral(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_TIPO_FUNCIONARIO_PUBLICO)) {
      return new CertificadoExtFuncionarioPublicoBancoCentral(certificado);
    } else if (certificateHasPolicy(certificado, Ext.OID_SELLADO_TIEMPO)) {
      return new CertificadoExtSelladoTiempoBancoCentral(certificado);
    }
  }
  return null;
}
