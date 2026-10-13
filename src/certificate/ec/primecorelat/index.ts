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
import { Certificado, esMiembroEmpresa, esPersonaJuridica, esPersonaNatural, esSelloElectronico, tipos } from '../../base.js';
import { certificateHasPolicy, verifySignature } from '../../cert-utils.js';
import { DatosUsuario } from '../../datos-usuario.js';
import { AttributeOIDs, CertificadoSubjImpl } from '../subj/index.js';
import { SubCa1CertPrimeCoreLat20262036, SubCa2CertPrimeCoreLat20262036 } from './certs.js';

/** Port of `CertificadoPrimeCoreLat` (OIDs). */
export const Subj = {
  OID_TIPO_PERSONA_NATURAL: '1.3.6.1.4.1.63542.2.1.1',
  OID_TIPO_MIEMBRO_EMPRESA: '1.3.6.1.4.1.63542.2.2.1',
  OID_TIPO_REPRESENTANTE_LEGAL: '1.3.6.1.4.1.63542.2.3.1',
  OID_TIPO_SELLO_ELECTRONICO: '1.3.6.1.4.1.63542.102.2.4.1',
} as const;

// ------------------------------------------------------------------ subj

export class CertificadoSubjPersonaNaturalPrimeCoreLat extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaNatural');
}

export class CertificadoSubjMiembroEmpresaPrimeCoreLat extends CertificadoSubjImpl {
  readonly tipos = tipos('MiembroEmpresa');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjPersonaJuridicaPrimeCoreLat extends CertificadoSubjImpl {
  readonly tipos = tipos('PersonaJuridica');

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }

  getCargo(): string {
    return this.getSubjectField(AttributeOIDs.OID_CARGO);
  }
}

export class CertificadoSubjSelloElectronicoPrimeCoreLat extends CertificadoSubjImpl {
  readonly tipos = tipos('SelloElectronico');

  getCommonName(): string {
    return this.getSubjectField(AttributeOIDs.OID_COMMON_NAME);
  }

  getRazonSocial(): string {
    return this.getSubjectField(AttributeOIDs.OID_ORGANIZACION);
  }
}

// --------------------------------------------------------------- factory

/** Port of `CertificadoDataFactoryPrimeCoreLat.getRootCertificate`. */
export function getRootCertificate(certificado: Certificate): Certificate | null {
  if (verifySignature(certificado, SubCa1CertPrimeCoreLat20262036)) return SubCa1CertPrimeCoreLat20262036;
  if (verifySignature(certificado, SubCa2CertPrimeCoreLat20262036)) return SubCa2CertPrimeCoreLat20262036;
  return null;
}

/** Port of `CertificadoDataFactoryPrimeCoreLat.getDatosUsuarioPrimeCoreLat`. */
export function getDatosUsuario(certificado: Certificate): DatosUsuario | null {
  let datosUsuario: DatosUsuario | null = null;
  const c = construir(certificado);
  if (c !== null) {
    datosUsuario = new DatosUsuario();
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
      if (esPersonaJuridica(c)) {
        datosUsuario.setTipoCertificado('Persona Jurídica');
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
  if (certificateHasPolicy(certificado, Subj.OID_TIPO_PERSONA_NATURAL)) {
    return new CertificadoSubjPersonaNaturalPrimeCoreLat(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_MIEMBRO_EMPRESA)) {
    return new CertificadoSubjMiembroEmpresaPrimeCoreLat(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_REPRESENTANTE_LEGAL)) {
    // Java: Representante Legal is built as Persona Jurídica
    return new CertificadoSubjPersonaJuridicaPrimeCoreLat(certificado);
  } else if (certificateHasPolicy(certificado, Subj.OID_TIPO_SELLO_ELECTRONICO)) {
    return new CertificadoSubjSelloElectronicoPrimeCoreLat(certificado);
  }
  return null;
}
