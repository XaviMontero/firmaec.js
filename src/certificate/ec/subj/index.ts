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
import { Certificado } from '../../base.js';

/** Port of `certificate.ec.subj.AttributeOIDs` (RESOLUCION-ARCOTEL-2024-0176). */
export const AttributeOIDs = {
  OID_COMMON_NAME: '2.5.4.3',
  OID_CEDULA_PASAPORTE: '2.5.4.5',
  OID_APELLIDOS: '2.5.4.4',
  OID_NOMBRES: '2.5.4.42',
  OID_PAIS: '2.5.4.6',
  OID_CIUDAD: '2.5.4.7',
  OID_RUC: '2.5.4.97',
  OID_ORGANIZACION: '2.5.4.10',
  OID_DEPARTAMENTO: '2.5.4.11',
  OID_CARGO: '2.5.4.12',
} as const;

/** Port of `certificate.ec.subj.CertificadoSubjImpl`: data read from the subject DN. */
export abstract class CertificadoSubjImpl extends Certificado {
  constructor(certificado: Certificate) {
    super(certificado);
    this.cargarSubjectName();
  }

  getCedulaPasaporte(): string {
    return this.getSubjectField(AttributeOIDs.OID_CEDULA_PASAPORTE);
  }

  getNombres(): string {
    return this.getSubjectField(AttributeOIDs.OID_NOMBRES);
  }

  getPrimerApellido(): string {
    return this.getSubjectField(AttributeOIDs.OID_APELLIDOS);
  }

  getSegundoApellido(): string {
    return '';
  }

  getDireccion(): string {
    return '';
  }

  getTelefono(): string {
    return '';
  }

  getCiudad(): string {
    return this.getSubjectField(AttributeOIDs.OID_CIUDAD);
  }

  getPais(): string {
    return this.getSubjectField(AttributeOIDs.OID_PAIS);
  }

  getRuc(): string {
    return this.getSubjectField(AttributeOIDs.OID_RUC);
  }
}
