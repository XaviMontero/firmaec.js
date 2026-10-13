import { describe, expect, it } from 'vitest';
import { AliasesNotFoundException, KeyStore, RubricaException } from '../../src/index.js';
import { PASSWORD, signers } from '../helpers/fixtures.js';
import { NameSpec, buildCertificate, createCa, ext, issue, keyPair, toP12 } from '../helpers/pki.js';

describe('KeyStore (PKCS#12)', () => {
  it('loads modern, legacy and EC files with the chain ordered leaf -> root', () => {
    for (const s of [signers.natural, signers.legacy, signers.ec]) {
      const ks = KeyStore.fromPkcs12(s.p12, PASSWORD);
      const e = ks.getEntry();
      expect(e.chain.map((c) => c.der.toString('hex'))).toEqual(s.signer.chain.map((c) => c.toString('hex')));
      expect(ks.aliases()).toEqual(['firmante']);
      expect(ks.getSigningAliases()).toEqual([{ alias: 'firmante', name: e.certificate.subject.getBcField('2.5.4.3') }]);
    }
  });

  it('builds the chain through intermediate CAs regardless of bag order', () => {
    const root = createCa([['CN', 'ROOT']], 'ks-root');
    const interKey = keyPair('ks-inter');
    const interName: NameSpec = [['CN', 'INTERMEDIA']];
    const inter = buildCertificate({
      subject: interName,
      issuer: { name: root.name, key: root.key.privateKey },
      publicKey: interKey.publicKey,
      extensions: [ext.basicConstraints(true)],
    });
    const leaf = issue({ name: interName, key: interKey, cert: inter }, [['CN', 'LEAF']], [], { label: 'ks-leaf' });
    // key's certificate first (localKeyId), then the CAs out of order
    const p12 = toP12({ ...leaf, chain: [leaf.cert, root.cert, inter] }, 'x');
    const e = KeyStore.fromPkcs12(p12, 'x').getEntry();
    expect(e.chain.map((c) => c.subjectPrincipal)).toEqual(['CN=LEAF', 'CN=INTERMEDIA', 'CN=ROOT']);
  });

  it('reports wrong passwords and unknown aliases', () => {
    expect(() => KeyStore.fromPkcs12(signers.natural.p12, 'mala')).toThrow(RubricaException);
    expect(() => KeyStore.fromPkcs12(signers.natural.p12, PASSWORD).getEntry('otro')).toThrow(AliasesNotFoundException);
    expect(() => KeyStore.fromPkcs12(Buffer.from('basura'), PASSWORD)).toThrow(RubricaException);
  });

  it('signing aliases require the digitalSignature key usage', () => {
    const root = createCa([['CN', 'ROOT2']], 'ks-root2');
    const leaf = issue(root, [['CN', 'SIN KU']], [], { label: 'ks-noku', withKeyUsage: false });
    expect(KeyStore.fromPkcs12(toP12(leaf, 'x'), 'x').getSigningAliases()).toEqual([]);
  });
});
