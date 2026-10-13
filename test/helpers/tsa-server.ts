/** Local RFC 3161 TSA (openssl ts) with optional basic auth, for e2e tests. */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createCa, ext, issue, toPem } from './pki.js';
import { tmpDir } from './oracle.js';

export interface TsaServer {
  url: string;
  requests: Array<{ authorization?: string }>;
  close(): Promise<void>;
}

export async function startTsa(opts: { user?: string; password?: string; status?: number } = {}): Promise<TsaServer> {
  const dir = tmpDir('tsa-');
  const ca = createCa([['C', 'EC'], ['O', 'TSA TEST CA'], ['CN', 'TSA ROOT']], 'tsa-ca');
  const tsa = issue(ca, [['C', 'EC'], ['O', 'TSA TEST'], ['CN', 'SELLADO DE TIEMPO TEST']], [
    { oid: '2.5.29.37', critical: true, value: Buffer.from('300a06082b06010505070308', 'hex') },
  ], { label: 'tsa', withKeyUsage: false });
  fs.writeFileSync(path.join(dir, 'tsa.pem'), toPem(tsa.cert));
  fs.writeFileSync(path.join(dir, 'ca.pem'), toPem(ca.cert));
  fs.writeFileSync(path.join(dir, 'tsa.key'), tsa.key.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string);
  fs.writeFileSync(path.join(dir, 'serial'), '01\n');
  fs.writeFileSync(
    path.join(dir, 'tsa.cnf'),
    `[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = ${dir}
serial = $dir/serial
signer_cert = $dir/tsa.pem
certs = $dir/ca.pem
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha1, sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
`,
  );
  const requests: TsaServer['requests'] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({ authorization: req.headers.authorization });
      if (opts.status) {
        res.writeHead(opts.status).end();
        return;
      }
      if (opts.user !== undefined) {
        const expected = 'Basic ' + Buffer.from(`${opts.user}:${opts.password ?? ''}`).toString('base64');
        if (req.headers.authorization !== expected) {
          res.writeHead(401).end();
          return;
        }
      }
      const q = path.join(dir, `q${requests.length}.tsq`);
      const r = path.join(dir, `r${requests.length}.tsr`);
      fs.writeFileSync(q, Buffer.concat(chunks));
      try {
        execFileSync('openssl', ['ts', '-reply', '-config', path.join(dir, 'tsa.cnf'), '-queryfile', q, '-out', r], {
          stdio: 'pipe',
        });
        res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' }).end(fs.readFileSync(r));
      } catch (e) {
        res.writeHead(500).end(String(e));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}/tsa`,
    requests,
    close: () =>
      new Promise((resolve) => {
        server.close(() => {
          fs.rmSync(dir, { recursive: true, force: true });
          resolve();
        });
      }),
  };
}
