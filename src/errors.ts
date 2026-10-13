/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

/** Port of `ec.gob.firmadigital.libreria.exceptions.*` used by the signing paths. */
export class RubricaException extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class EntidadCertificadoraNoValidaException extends RubricaException {}
export class CertificadoInvalidoException extends RubricaException {}
export class InvalidFormatException extends RubricaException {}
export class AliasesNotFoundException extends RubricaException {}
export class SignatureVerificationException extends RubricaException {}
/** TSA (sello de tiempo) errors, Java threw `GeneralSecurityException` with these messages. */
export class TsaException extends RubricaException {}
