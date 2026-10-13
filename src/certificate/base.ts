/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import { Certificate } from '../x509/certificate.js';
import { getExtensionValue, getSubjectAlternativeName } from './cert-utils.js';

/**
 * Port of `ec.gob.firmadigital.libreria.certificate.Certificado` (abstract base
 * of every CA specific certificate wrapper).
 */
export abstract class Certificado {
  private subjectLoaded = false;

  /** Java marker interfaces implemented by the concrete class. */
  abstract readonly tipos: ReadonlySet<TipoCertificado>;

  constructor(readonly certificado: Certificate) {}

  protected cargarSubjectName(): void {
    this.subjectLoaded = true;
  }

  protected getExtensionField(oid: string): string {
    return getExtensionValue(this.certificado, oid) ?? '';
  }

  protected getSubjectAlternativeName(oid: string): string {
    return getSubjectAlternativeName(this.certificado, oid) ?? '';
  }

  protected getSubjectField(oid: string): string {
    if (!this.subjectLoaded) {
      // Java: subjectName is null unless cargarSubjectName() was called
      throw new Error('NullPointerException: subjectName no cargado');
    }
    return this.certificado.subject.getBcField(oid) ?? '';
  }
}

/** Java marker interfaces under `certificate/ec`. */
export type TipoCertificado =
  | 'PersonaNatural'
  | 'PersonaJuridica'
  | 'MiembroEmpresa'
  | 'RepresentanteLegal'
  | 'FuncionarioPublico'
  | 'SelloElectronico'
  | 'SelladoTiempo';

/** Java interface inheritance: each marker interface extends these. */
const SUPER: Record<TipoCertificado, TipoCertificado[]> = {
  PersonaNatural: [],
  PersonaJuridica: ['PersonaNatural'],
  MiembroEmpresa: ['PersonaNatural'],
  RepresentanteLegal: ['PersonaJuridica'],
  FuncionarioPublico: ['PersonaNatural'],
  SelloElectronico: ['PersonaNatural'],
  SelladoTiempo: ['PersonaNatural'],
};

/** Set of implemented interfaces, including inherited ones (so `instanceof` semantics hold). */
export function tipos(...t: TipoCertificado[]): ReadonlySet<TipoCertificado> {
  const out = new Set<TipoCertificado>();
  const add = (x: TipoCertificado) => {
    if (out.has(x)) return;
    out.add(x);
    SUPER[x].forEach(add);
  };
  t.forEach(add);
  return out;
}

/* Port of the interfaces in certificate/ec. Getter names follow Java. */

export interface CertificadoPersonaNatural {
  getRuc(): string;
  getCedulaPasaporte(): string;
  getNombres(): string;
  getPrimerApellido(): string;
  getSegundoApellido(): string;
  getDireccion(): string;
  getTelefono(): string;
  getCiudad(): string;
  getPais(): string;
}

export interface CertificadoPersonaJuridica extends CertificadoPersonaNatural {
  getRazonSocial(): string;
  getCargo(): string;
}

export interface CertificadoMiembroEmpresa extends CertificadoPersonaNatural {
  getRazonSocial(): string;
  getCargo(): string;
}

export interface CertificadoRepresentanteLegal extends CertificadoPersonaJuridica {}

export interface CertificadoFuncionarioPublico extends CertificadoPersonaNatural {
  getInstitucion(): string;
  getCargo(): string;
  getRazonSocial(): string;
}

export interface CertificadoSelloElectronico extends CertificadoPersonaNatural {
  getRazonSocial(): string;
  getCommonName(): string;
}

export interface CertificadoSelladoTiempo extends CertificadoPersonaNatural {
  getRazonSocial(): string;
  getCommonName(): string;
}

type Accessors = Record<string, () => string>;

function is<T>(c: Certificado | null | undefined, t: TipoCertificado): c is Certificado & T {
  return !!c && c.tipos.has(t);
}

export const esPersonaNatural = (c: Certificado | null | undefined) =>
  is<CertificadoPersonaNatural & Accessors>(c, 'PersonaNatural');
export const esPersonaJuridica = (c: Certificado | null | undefined) =>
  is<CertificadoPersonaJuridica & Accessors>(c, 'PersonaJuridica');
export const esMiembroEmpresa = (c: Certificado | null | undefined) =>
  is<CertificadoMiembroEmpresa & Accessors>(c, 'MiembroEmpresa');
export const esRepresentanteLegal = (c: Certificado | null | undefined) =>
  is<CertificadoRepresentanteLegal & Accessors>(c, 'RepresentanteLegal');
export const esFuncionarioPublico = (c: Certificado | null | undefined) =>
  is<CertificadoFuncionarioPublico & Accessors>(c, 'FuncionarioPublico');
export const esSelloElectronico = (c: Certificado | null | undefined) =>
  is<CertificadoSelloElectronico & Accessors>(c, 'SelloElectronico');
export const esSelladoTiempo = (c: Certificado | null | undefined) =>
  is<CertificadoSelladoTiempo & Accessors>(c, 'SelladoTiempo');
