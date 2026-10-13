/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import zlib from 'node:zlib';
import { PDFDocument, PDFObject, PDFRef } from 'pdf-lib';
import { InvalidFormatException } from '../errors.js';

/**
 * Incremental update ("append mode", like iText `StampingProperties.useAppendMode()`):
 * the original bytes are kept untouched and the new/modified objects are written
 * after them, followed by a new cross-reference section linked with /Prev.
 */
export class IncrementalPdf {
  readonly doc: PDFDocument;
  readonly original: Buffer;
  readonly prevStartXref: number;
  readonly usesXrefStream: boolean;
  private readonly originalLargest: number;
  private readonly changed = new Set<string>();
  /** Objects written by hand (raw bytes between `obj` and `endobj`). */
  private readonly rawObjects = new Map<number, { ref: PDFRef; body: Buffer }>();

  private constructor(original: Buffer, doc: PDFDocument) {
    this.original = original;
    this.doc = doc;
    this.prevStartXref = findStartXref(original);
    this.usesXrefStream = !/^\s*xref/.test(original.subarray(this.prevStartXref, this.prevStartXref + 16).toString('latin1'));
    this.originalLargest = doc.context.largestObjectNumber;
  }

  static async load(bytes: Uint8Array): Promise<IncrementalPdf> {
    const original = Buffer.from(bytes);
    if (!original.subarray(0, 1024).toString('latin1').includes('%PDF-')) {
      throw new InvalidFormatException('El documento no es un PDF');
    }
    let doc: PDFDocument;
    try {
      doc = await PDFDocument.load(original, { updateMetadata: false, ignoreEncryption: true, throwOnInvalidObject: false });
    } catch (e) {
      throw new InvalidFormatException('No se ha podido leer el PDF', { cause: e });
    }
    if (doc.context.trailerInfo.Encrypt) {
      throw new InvalidFormatException('El PDF está cifrado; no se admite firmarlo');
    }
    return new IncrementalPdf(original, doc);
  }

  get context() {
    return this.doc.context;
  }

  /** Marks an existing indirect object as modified so it is re-written. */
  markChanged(ref: PDFRef): void {
    this.changed.add(ref.toString());
  }

  /** Reserves an object number for an object whose body is produced by hand. */
  reserveRaw(): PDFRef {
    return this.context.nextRef();
  }

  setRaw(ref: PDFRef, body: Buffer): void {
    this.rawObjects.set(ref.objectNumber, { ref, body });
  }

  /** Serializes the update. Returns the full file and the offset of every written object. */
  build(): { bytes: Buffer; offsets: Map<number, number> } {
    const ctx = this.context;
    const entries: Array<{ ref: PDFRef; body: Buffer | PDFObject }> = [];
    for (const [ref, obj] of ctx.enumerateIndirectObjects()) {
      if (this.rawObjects.has(ref.objectNumber)) continue;
      if (ref.objectNumber > this.originalLargest || this.changed.has(ref.toString())) {
        entries.push({ ref, body: obj });
      }
    }
    for (const raw of this.rawObjects.values()) entries.push({ ref: raw.ref, body: raw.body });
    entries.sort((a, b) => a.ref.objectNumber - b.ref.objectNumber);

    const chunks: Buffer[] = [this.original];
    let offset = this.original.length;
    const push = (b: Buffer) => {
      chunks.push(b);
      offset += b.length;
    };
    if (this.original[this.original.length - 1] !== 0x0a && this.original[this.original.length - 1] !== 0x0d) {
      push(Buffer.from('\n'));
    }
    const offsets = new Map<number, number>();
    for (const { ref, body } of entries) {
      offsets.set(ref.objectNumber, offset);
      push(Buffer.from(`${ref.objectNumber} ${ref.generationNumber} obj\n`, 'latin1'));
      push(Buffer.isBuffer(body) ? body : serialize(body));
      push(Buffer.from('\nendobj\n', 'latin1'));
    }

    const size = ctx.largestObjectNumber + 1;
    const info = ctx.trailerInfo;
    const trailerParts: string[] = [`/Size ${size}`, `/Root ${info.Root}`];
    if (info.Info) trailerParts.push(`/Info ${info.Info}`);
    if (info.ID) trailerParts.push(`/ID ${info.ID}`);
    trailerParts.push(`/Prev ${this.prevStartXref}`);

    const sorted = [...offsets.entries()].sort((a, b) => a[0] - b[0]);
    const gens = new Map(entries.map((e) => [e.ref.objectNumber, e.ref.generationNumber]));
    const xrefOffset = offset;
    if (!this.usesXrefStream) {
      let xref = 'xref\n';
      for (const [start, group] of groups(sorted)) {
        xref += `${start} ${group.length}\n`;
        for (const [num, off] of group) {
          xref += `${String(off).padStart(10, '0')} ${String(gens.get(num)).padStart(5, '0')} n\r\n`;
        }
      }
      push(Buffer.from(xref + `trailer\n<<${trailerParts.join(' ')}>>\nstartxref\n${xrefOffset}\n%%EOF\n`, 'latin1'));
    } else {
      // the xref stream is an object itself
      const xrefNum = size;
      const all = [...sorted, [xrefNum, xrefOffset] as [number, number]];
      const offBytes = Math.max(2, Math.ceil(Math.log2(xrefOffset + 2) / 8));
      const rows: Buffer[] = [];
      const index: number[] = [];
      for (const [start, group] of groups(all)) {
        index.push(start, group.length);
        for (const [num, off] of group) {
          const row = Buffer.alloc(1 + offBytes + 2);
          row[0] = 1;
          row.writeUIntBE(off, 1, offBytes);
          row.writeUInt16BE(num === xrefNum ? 0 : gens.get(num)!, 1 + offBytes);
          rows.push(row);
        }
      }
      const data = zlib.deflateSync(Buffer.concat(rows));
      const dict = [
        '/Type /XRef',
        `/Size ${size + 1}`,
        `/Root ${info.Root}`,
        ...(info.Info ? [`/Info ${info.Info}`] : []),
        ...(info.ID ? [`/ID ${info.ID}`] : []),
        `/Prev ${this.prevStartXref}`,
        `/Index [${index.join(' ')}]`,
        `/W [1 ${offBytes} 2]`,
        '/Filter /FlateDecode',
        `/Length ${data.length}`,
      ].join(' ');
      push(Buffer.from(`${xrefNum} 0 obj\n<<${dict}>>\nstream\n`, 'latin1'));
      push(data);
      push(Buffer.from(`\nendstream\nendobj\nstartxref\n${xrefOffset}\n%%EOF\n`, 'latin1'));
    }
    return { bytes: Buffer.concat(chunks), offsets };
  }
}

export function serialize(obj: PDFObject): Buffer {
  const buf = new Uint8Array(obj.sizeInBytes());
  obj.copyBytesInto(buf, 0);
  return Buffer.from(buf);
}

/** Groups consecutive object numbers for the xref subsections. */
function groups(sorted: Array<[number, number]>): Array<[number, Array<[number, number]>]> {
  const out: Array<[number, Array<[number, number]>]> = [];
  for (const entry of sorted) {
    const last = out[out.length - 1];
    if (last && last[1][last[1].length - 1][0] === entry[0] - 1) last[1].push(entry);
    else out.push([entry[0], [entry]]);
  }
  return out;
}

export function findStartXref(bytes: Buffer): number {
  const tail = bytes.subarray(Math.max(0, bytes.length - 2048)).toString('latin1');
  const idx = tail.lastIndexOf('startxref');
  if (idx < 0) throw new InvalidFormatException('PDF sin startxref');
  const m = /startxref\s+(\d+)/.exec(tail.substring(idx));
  if (!m) throw new InvalidFormatException('PDF con startxref invalido');
  return parseInt(m[1], 10);
}
