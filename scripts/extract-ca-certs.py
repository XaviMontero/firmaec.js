#!/usr/bin/env python3
"""Extracts the CA certificates embedded in the Java sources (cert/*.java)
into src/certificate/ec/<ca>/certs.ts. Usage: extract-ca-certs.py <java-src-root>"""
import os, re, sys, glob
root = sys.argv[1].rstrip('/') + '/ec/gob/firmadigital/libreria/certificate/ec'
out_root = os.path.join(os.path.dirname(__file__), '..', 'src', 'certificate', 'ec')
HEADER = '''/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

// Generado por scripts/extract-ca-certs.py desde certificate/ec/{ca}/cert/*.java. No editar.

import {{ Certificate }} from '../../../x509/certificate.js';

'''
total = 0
for ca_dir in sorted(glob.glob(root + '/*/cert')):
    ca = ca_dir.split('/')[-2]
    entries = []
    for f in sorted(glob.glob(ca_dir + '/*.java')):
        src = open(f, encoding='utf-8').read()
        parts = re.findall(r'append\("((?:[^"\\]|\\.)*)"\)', src)
        pem = ''.join(parts).replace('\\n', '\n').replace('\\r', '')
        if 'BEGIN CERTIFICATE' not in pem:
            print('WARN sin PEM', f, file=sys.stderr); continue
        entries.append((os.path.basename(f)[:-5], pem.strip() + '\n'))
    os.makedirs(os.path.join(out_root, ca), exist_ok=True)
    with open(os.path.join(out_root, ca, 'certs.ts'), 'w') as o:
        o.write(HEADER.format(ca=ca))
        for name, pem in entries:
            o.write(f'export const {name} = new Certificate(`{pem}`);\n\n')
    total += len(entries)
    print(ca, len(entries))
print('total', total)
