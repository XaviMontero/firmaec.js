/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

/** Port of `certificate.to.DatosUsuario`. Setters keep the Java normalizations. */
export class DatosUsuario {
  tipoCertificado: string | null = null;
  private _cedula: string | null = null;
  nombre: string | null = null;
  apellido: string | null = null;
  private _ruc: string | null = '';
  razonSocial: string | null = '';
  institucion: string | null = '';
  cargo: string | null = '';
  commonName: string | null = '';
  email: string | null = '';
  certificadoDigitalValido = false;
  fechaFirmaArchivoP7M: string | null = null;

  get cedula(): string | null {
    return this._cedula;
  }

  set cedula(cedula: string | null) {
    this._cedula = cedula === null || cedula === undefined ? null : cedula.replaceAll('IDCEC-', '').replaceAll('PASEC-', '');
  }

  get ruc(): string | null {
    return this._ruc;
  }

  set ruc(ruc: string | null) {
    this._ruc = ruc === null || ruc === undefined ? null : ruc.replaceAll('VATEC-', '');
  }

  // Java style accessors, handy when porting code 1:1
  setTipoCertificado(v: string | null) { this.tipoCertificado = v; }
  setCedula(v: string | null) { this.cedula = v; }
  setNombre(v: string | null) { this.nombre = v; }
  setApellido(v: string | null) { this.apellido = v; }
  setRuc(v: string | null) { this.ruc = v; }
  setRazonSocial(v: string | null) { this.razonSocial = v; }
  setInstitucion(v: string | null) { this.institucion = v; }
  setCargo(v: string | null) { this.cargo = v; }
  setCommonName(v: string | null) { this.commonName = v; }
  setEmail(v: string | null) { this.email = v; }
  setCertificadoDigitalValido(v: boolean) { this.certificadoDigitalValido = v; }
  getCedula() { return this.cedula; }
  getNombre() { return this.nombre; }
  getApellido() { return this.apellido; }
  getRazonSocial() { return this.razonSocial; }

  toJSON() {
    return {
      tipoCertificado: this.tipoCertificado,
      cedula: this.cedula,
      nombre: this.nombre,
      apellido: this.apellido,
      ruc: this.ruc,
      razonSocial: this.razonSocial,
      institucion: this.institucion,
      cargo: this.cargo,
      commonName: this.commonName,
      email: this.email,
      certificadoDigitalValido: this.certificadoDigitalValido,
    };
  }
}
