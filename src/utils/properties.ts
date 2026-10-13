/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

/** Port of `config.rubrica.properties` (read by `PropertiesUtils.getConfig()`). */
export const CONFIG = {
  time_out: 10000,
  tsa_url: 'https://tsa.uanatacaec.com/tsa/timestamp',
  version_url: 'https://api.firmadigital.gob.ec/api/version',
  fecha_hora_url: 'https://api.firmadigital.gob.ec/api/fecha-hora',
  certificado_revocado_url: 'https://api.firmadigital.gob.ec/api/certificado/fechaRevocado',
  version: '5.2.0',
  fecha: '2026-08-15',
} as const;

/** Java `Integer.parseInt` (throws on anything that is not an optional sign + digits). */
export function parseJavaInt(s: string): number {
  if (!/^[+-]?\d+$/.test(s)) throw new Error(`NumberFormatException: For input string: "${s}"`);
  const n = parseInt(s, 10);
  if (n > 2147483647 || n < -2147483648) throw new Error(`NumberFormatException: For input string: "${s}"`);
  return n;
}

/**
 * Port of `Utils.getSignTime`: ISO-8601 with offset (`DateTimeFormatter.ISO_OFFSET_DATE_TIME`).
 * Returns null when the value does not follow the pattern (Java then used "now").
 */
export function parseSignTime(fechaHora: string): Date | null {
  const m =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2}(?::\d{2})?)$/.exec(fechaHora);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac, off] = m;
  const ms = frac ? Math.floor(parseInt(frac.padEnd(3, '0').substring(0, 3), 10)) : 0;
  let offsetSec = 0;
  if (off !== 'Z') {
    const sign = off[0] === '-' ? -1 : 1;
    const [oh, om, os] = off.substring(1).split(':').map((x) => parseInt(x, 10));
    offsetSec = sign * (oh * 3600 + om * 60 + (os ?? 0));
  }
  const month = +mo;
  const day = +d;
  if (month < 1 || month > 12 || day < 1 || day > 31 || +h > 23 || +mi > 59 || (s && +s > 59)) return null;
  const utc = Date.UTC(+y, month - 1, day, +h, +mi, s ? +s : 0, ms) - offsetSec * 1000;
  const check = new Date(Date.UTC(+y, month - 1, day));
  if (check.getUTCDate() !== day) return null; // e.g. 2026-02-30
  return new Date(utc);
}
