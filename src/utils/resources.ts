/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Root of the bundled resources (fonts), works from src/ (tsx) and dist/. */
const RESOURCES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../resources');

const cache = new Map<string, Buffer>();

export function loadResource(name: string): Buffer {
  let b = cache.get(name);
  if (!b) {
    b = fs.readFileSync(path.join(RESOURCES, name));
    cache.set(name, b);
  }
  return b;
}
