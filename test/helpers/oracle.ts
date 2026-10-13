/** Runs the Java FirmaEC oracle (oracle/Oracle.java over the original library). */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Certificate } from '../../src/x509/certificate.js';
import { getDatosUsuarios, getNombreCA } from '../../src/certificate/cert-ec-utils.js';
import { getCN, getEmail } from '../../src/certificate/cert-utils.js';
import { toPem } from './pki.js';

const ORACLE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../oracle/oracle.sh');

export const oracleAvailable = fs.existsSync(path.resolve(path.dirname(ORACLE), 'classes/Oracle.class'));

export function oracle<T = unknown>(...args: string[]): T {
  const out = execFileSync(ORACLE, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const line = out.trim().split('\n').filter((l) => l.startsWith('{') || l.startsWith('[')).pop();
  if (!line) throw new Error('oracle sin salida JSON: ' + out);
  return JSON.parse(line) as T;
}

export function tmpDir(prefix = 'firmaec-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export interface DatosResult {
  entidad?: string;
  datos?: Record<string, unknown> | null;
  error?: string;
}

/** Writes the certs to disk and runs the oracle `datos` command on all of them at once. */
export function oracleDatos(certs: Buffer[]): DatosResult[] {
  const dir = tmpDir();
  try {
    const files = certs.map((c, i) => {
      const f = path.join(dir, `c${i}.pem`);
      fs.writeFileSync(f, toPem(c));
      return f;
    });
    return oracle<DatosResult[]>('datos', ...files);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Same shape as the oracle output, computed by the TS port. */
export function jsDatos(certDer: Buffer): DatosResult {
  const cert = new Certificate(certDer);
  const res: DatosResult = {};
  try {
    res.entidad = getNombreCA(cert);
  } catch (e) {
    return { error: String(e) };
  }
  try {
    const d = getDatosUsuarios(cert);
    res.datos = d ? (d.toJSON() as unknown as Record<string, unknown>) : null;
  } catch (e) {
    res.error = (e as Error).name + ': ' + (e as Error).message;
  }
  return res;
}

export function oracleX500(certs: Buffer[]) {
  const dir = tmpDir();
  try {
    const files = certs.map((c, i) => {
      const f = path.join(dir, `c${i}.pem`);
      fs.writeFileSync(f, toPem(c));
      return f;
    });
    return oracle<Array<{ issuer: string; issuerRfc2253: string; subject: string; cn: string; email: string | null }>>(
      'x500',
      ...files,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export function jsX500(certDer: Buffer) {
  const c = new Certificate(certDer);
  return {
    issuer: c.issuerPrincipal,
    issuerRfc2253: c.issuer.toRfc2253(),
    subject: c.subjectPrincipal,
    cn: getCN(c),
    email: getEmail(c),
  };
}
