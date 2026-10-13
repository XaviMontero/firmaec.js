/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import crypto from 'node:crypto';
import { PDFArray, PDFContext, PDFName, PDFNumber, PDFRef, PDFString } from 'pdf-lib';

/**
 * TrueType font embedded as Type0/Identity-H the way iText does it: glyph ids
 * are kept (CIDToGIDMap /Identity), unused glyph outlines are emptied, there is
 * no OpenType shaping and characters without a glyph are skipped.
 */

interface TableEntry {
  tag: string;
  offset: number;
  length: number;
}

const KEEP_TABLES = ['cmap', 'cvt ', 'fpgm', 'glyf', 'head', 'hhea', 'hmtx', 'loca', 'maxp', 'prep', 'OS/2'];

export class TrueTypeFont {
  readonly tables = new Map<string, TableEntry>();
  readonly unitsPerEm: number;
  readonly numGlyphs: number;
  readonly indexToLocFormat: number;
  readonly advances: number[];
  readonly postscriptName: string;
  readonly cmap = new Map<number, number>();
  /** hhea / OS2 metrics (font units). */
  readonly hheaAscender: number;
  readonly hheaDescender: number;
  readonly winAscent: number;
  readonly winDescent: number;
  readonly capHeight: number;
  readonly bbox: [number, number, number, number];
  readonly italicAngle: number;
  readonly isFixedPitch: boolean;
  readonly weightClass: number;

  constructor(readonly data: Buffer) {
    const numTables = data.readUInt16BE(4);
    for (let i = 0; i < numTables; i++) {
      const p = 12 + i * 16;
      const tag = data.toString('latin1', p, p + 4);
      this.tables.set(tag, { tag, offset: data.readUInt32BE(p + 8), length: data.readUInt32BE(p + 12) });
    }
    const head = this.table('head');
    this.unitsPerEm = head.readUInt16BE(18);
    this.bbox = [head.readInt16BE(36), head.readInt16BE(38), head.readInt16BE(40), head.readInt16BE(42)];
    this.indexToLocFormat = head.readInt16BE(50);
    this.numGlyphs = this.table('maxp').readUInt16BE(4);
    const hhea = this.table('hhea');
    this.hheaAscender = hhea.readInt16BE(4);
    this.hheaDescender = hhea.readInt16BE(6);
    const numHMetrics = hhea.readUInt16BE(34);
    const hmtx = this.table('hmtx');
    this.advances = [];
    let last = 0;
    for (let g = 0; g < this.numGlyphs; g++) {
      if (g < numHMetrics) last = hmtx.readUInt16BE(g * 4);
      this.advances.push(last);
    }
    const os2 = this.table('OS/2');
    this.weightClass = os2.readUInt16BE(4);
    this.winAscent = os2.readUInt16BE(74);
    this.winDescent = os2.readUInt16BE(76);
    this.capHeight = os2.length >= 90 ? os2.readInt16BE(88) : this.hheaAscender;
    const post = this.table('post');
    this.italicAngle = post.readInt32BE(4) / 65536;
    this.isFixedPitch = post.readUInt32BE(12) !== 0;
    this.postscriptName = this.readPostscriptName();
    this.readCmap();
  }

  table(tag: string): Buffer {
    const t = this.tables.get(tag);
    if (!t) throw new Error('Tabla TrueType ausente: ' + tag);
    return this.data.subarray(t.offset, t.offset + t.length);
  }

  private readPostscriptName(): string {
    const name = this.table('name');
    const count = name.readUInt16BE(2);
    const strOffset = name.readUInt16BE(4);
    for (let i = 0; i < count; i++) {
      const p = 6 + i * 12;
      const platform = name.readUInt16BE(p);
      const nameId = name.readUInt16BE(p + 6);
      const len = name.readUInt16BE(p + 8);
      const off = name.readUInt16BE(p + 10);
      if (nameId !== 6) continue;
      const raw = name.subarray(strOffset + off, strOffset + off + len);
      if (platform === 3 || platform === 0) {
        const b = Buffer.from(raw);
        b.swap16();
        return b.toString('utf16le');
      }
      return raw.toString('latin1');
    }
    return 'Font';
  }

  private readCmap(): void {
    const cmap = this.table('cmap');
    const n = cmap.readUInt16BE(2);
    let best: { off: number; fmt: number } | null = null;
    for (let i = 0; i < n; i++) {
      const p = 4 + i * 8;
      const platform = cmap.readUInt16BE(p);
      const encoding = cmap.readUInt16BE(p + 2);
      const off = cmap.readUInt32BE(p + 4);
      const fmt = cmap.readUInt16BE(off);
      if (platform === 3 && encoding === 10 && fmt === 12) best = { off, fmt };
      else if (!best && ((platform === 3 && encoding === 1) || platform === 0) && (fmt === 4 || fmt === 12)) best = { off, fmt };
    }
    if (!best) throw new Error('cmap Unicode no soportado');
    const t = cmap.subarray(best.off);
    if (best.fmt === 4) {
      const segX2 = t.readUInt16BE(6);
      const ends = 14;
      const starts = ends + segX2 + 2;
      const deltas = starts + segX2;
      const rangeOffs = deltas + segX2;
      for (let s = 0; s < segX2 / 2; s++) {
        const end = t.readUInt16BE(ends + s * 2);
        const start = t.readUInt16BE(starts + s * 2);
        const delta = t.readInt16BE(deltas + s * 2);
        const ro = t.readUInt16BE(rangeOffs + s * 2);
        for (let c = start; c <= end && c !== 0xffff; c++) {
          let g: number;
          if (ro === 0) g = (c + delta) & 0xffff;
          else {
            const gp = rangeOffs + s * 2 + ro + (c - start) * 2;
            g = t.readUInt16BE(gp);
            if (g !== 0) g = (g + delta) & 0xffff;
          }
          if (g !== 0) this.cmap.set(c, g);
        }
      }
    } else {
      const groups = t.readUInt32BE(12);
      for (let i = 0; i < groups; i++) {
        const p = 16 + i * 12;
        const start = t.readUInt32BE(p);
        const end = t.readUInt32BE(p + 4);
        const g0 = t.readUInt32BE(p + 8);
        for (let c = start; c <= end; c++) this.cmap.set(c, g0 + (c - start));
      }
    }
  }

  /** Font units -> 1000 units, truncated like iText. */
  scale(v: number): number {
    return Math.trunc((v * 1000) / this.unitsPerEm);
  }

  glyphOffset(g: number): [number, number] {
    const loca = this.table('loca');
    if (this.indexToLocFormat === 0) return [loca.readUInt16BE(g * 2) * 2, loca.readUInt16BE(g * 2 + 2) * 2];
    return [loca.readUInt32BE(g * 4), loca.readUInt32BE(g * 4 + 4)];
  }

  /** Component glyphs of a composite glyph. */
  components(g: number): number[] {
    const [a, b] = this.glyphOffset(g);
    if (b <= a) return [];
    const glyf = this.table('glyf');
    const d = glyf.subarray(a, b);
    if (d.readInt16BE(0) >= 0) return [];
    const out: number[] = [];
    let p = 10;
    while (true) {
      const flags = d.readUInt16BE(p);
      out.push(d.readUInt16BE(p + 2));
      p += 4 + (flags & 0x1 ? 4 : 2);
      if (flags & 0x8) p += 2;
      else if (flags & 0x40) p += 4;
      else if (flags & 0x80) p += 8;
      if (!(flags & 0x20)) break;
    }
    return out;
  }

  /** Builds a FontFile2 keeping glyph ids; only `used` glyphs (+ components, + .notdef) keep outlines. */
  subset(used: Set<number>): Buffer {
    const keep = new Set<number>([0]);
    const stack = [...used];
    while (stack.length) {
      const g = stack.pop()!;
      if (keep.has(g) && g !== 0) continue;
      keep.add(g);
      stack.push(...this.components(g).filter((c) => !keep.has(c)));
    }
    const glyf = this.table('glyf');
    const parts: Buffer[] = [];
    const loca = Buffer.alloc((this.numGlyphs + 1) * 4);
    let off = 0;
    for (let g = 0; g < this.numGlyphs; g++) {
      loca.writeUInt32BE(off, g * 4);
      if (keep.has(g)) {
        const [a, b] = this.glyphOffset(g);
        let data = glyf.subarray(a, b);
        if (data.length % 4) data = Buffer.concat([data, Buffer.alloc(4 - (data.length % 4))]);
        parts.push(data);
        off += data.length;
      }
    }
    loca.writeUInt32BE(off, this.numGlyphs * 4);
    const newTables = new Map<string, Buffer>();
    for (const tag of KEEP_TABLES) {
      if (!this.tables.has(tag)) continue;
      if (tag === 'glyf') newTables.set(tag, Buffer.concat(parts));
      else if (tag === 'loca') newTables.set(tag, loca);
      else if (tag === 'head') {
        const head = Buffer.from(this.table('head'));
        head.writeUInt32BE(0, 8); // checksumAdjustment, fixed below
        head.writeInt16BE(1, 50); // long loca
        newTables.set(tag, head);
      } else newTables.set(tag, Buffer.from(this.table(tag)));
    }
    return assembleSfnt(newTables);
  }
}

function checksum(b: Buffer): number {
  const padded = b.length % 4 ? Buffer.concat([b, Buffer.alloc(4 - (b.length % 4))]) : b;
  let sum = 0;
  for (let i = 0; i < padded.length; i += 4) sum = (sum + padded.readUInt32BE(i)) >>> 0;
  return sum;
}

function assembleSfnt(tables: Map<string, Buffer>): Buffer {
  const tags = [...tables.keys()].sort();
  const n = tags.length;
  let pow = 1;
  let log = 0;
  while (pow * 2 <= n) {
    pow *= 2;
    log++;
  }
  const header = Buffer.alloc(12 + n * 16);
  header.writeUInt32BE(0x00010000, 0);
  header.writeUInt16BE(n, 4);
  header.writeUInt16BE(pow * 16, 6);
  header.writeUInt16BE(log, 8);
  header.writeUInt16BE(n * 16 - pow * 16, 10);
  const bodies: Buffer[] = [];
  let offset = header.length;
  tags.forEach((tag, i) => {
    const data = tables.get(tag)!;
    const p = 12 + i * 16;
    header.write(tag, p, 'latin1');
    header.writeUInt32BE(checksum(data), p + 4);
    header.writeUInt32BE(offset, p + 8);
    header.writeUInt32BE(data.length, p + 12);
    const padded = data.length % 4 ? Buffer.concat([data, Buffer.alloc(4 - (data.length % 4))]) : data;
    bodies.push(padded);
    offset += padded.length;
  });
  const font = Buffer.concat([header, ...bodies]);
  const headIdx = tags.indexOf('head');
  if (headIdx >= 0) {
    const headOff = header.readUInt32BE(12 + headIdx * 16 + 8);
    font.writeUInt32BE((0xb1b0afba - checksum(font)) >>> 0, headOff + 8);
  }
  return font;
}

/** A font resource for one PDF: tracks used glyphs and writes the Type0 font at the end. */
export class PdfTrueTypeFont {
  readonly ref: PDFRef;
  private readonly used = new Map<number, string>();

  constructor(
    readonly font: TrueTypeFont,
    private readonly context: PDFContext,
  ) {
    this.ref = context.nextRef();
  }

  /** Ascent / descent iText uses for layout (usWin metrics in 1000 units). */
  get layoutAscent(): number {
    return this.font.scale(this.font.winAscent);
  }

  get layoutDescent(): number {
    return -this.font.scale(this.font.winDescent);
  }

  /** Glyphs for the text; characters missing in the font are skipped (as iText does). */
  glyphs(text: string): Array<{ gid: number; ch: string }> {
    const out: Array<{ gid: number; ch: string }> = [];
    for (const ch of text) {
      const gid = this.font.cmap.get(ch.codePointAt(0)!);
      if (gid !== undefined && gid !== 0) out.push({ gid, ch });
    }
    return out;
  }

  width(text: string, size: number): number {
    let w = 0;
    for (const { gid } of this.glyphs(text)) w += this.font.scale(this.font.advances[gid]);
    return (w * size) / 1000;
  }

  /** Hex string operand for Tj. */
  encode(text: string): string {
    let hex = '';
    for (const { gid, ch } of this.glyphs(text)) {
      if (!this.used.has(gid)) this.used.set(gid, ch);
      hex += gid.toString(16).padStart(4, '0');
    }
    return '<' + hex + '>';
  }

  /** Writes the font objects into the context (call after all text was encoded). */
  embed(): void {
    const ctx = this.context;
    const f = this.font;
    const gids = [...this.used.keys()].sort((a, b) => a - b);
    const tag = crypto
      .createHash('sha1')
      .update(f.postscriptName + gids.join(','))
      .digest()
      .subarray(0, 6)
      .map((b) => 65 + (b % 26));
    const baseFont = Buffer.from(tag).toString('latin1') + '+' + f.postscriptName;
    const fontFile = f.subset(new Set(gids));
    const fontFileRef = ctx.register(ctx.flateStream(fontFile, { Length1: fontFile.length }));
    let flags = 32;
    if (f.isFixedPitch) flags |= 1;
    if (f.italicAngle !== 0) flags |= 64;
    if (f.weightClass >= 700) flags |= 262144;
    const descriptor = ctx.register(
      ctx.obj({
        Type: 'FontDescriptor',
        FontName: PDFName.of(baseFont),
        Flags: flags,
        FontBBox: f.bbox.map((v) => f.scale(v)),
        ItalicAngle: f.italicAngle,
        Ascent: f.scale(f.hheaAscender),
        Descent: f.scale(f.hheaDescender),
        CapHeight: f.scale(f.capHeight),
        StemV: 80,
        FontFile2: fontFileRef,
      }),
    );
    const w = ctx.obj([]) as PDFArray;
    for (const g of gids) {
      w.push(PDFNumber.of(g));
      w.push(ctx.obj([f.scale(f.advances[g])]));
    }
    const cid = ctx.register(
      ctx.obj({
        Type: 'Font',
        Subtype: 'CIDFontType2',
        BaseFont: PDFName.of(baseFont),
        CIDSystemInfo: { Registry: PDFString.of('Adobe'), Ordering: PDFString.of('Identity'), Supplement: 0 },
        FontDescriptor: descriptor,
        CIDToGIDMap: 'Identity',
        DW: 1000,
        W: w,
      }),
    );
    const toUnicode = ctx.register(ctx.flateStream(Buffer.from(toUnicodeCMap(this.used), 'latin1'), {}));
    ctx.assign(
      this.ref,
      ctx.obj({
        Type: 'Font',
        Subtype: 'Type0',
        BaseFont: PDFName.of(baseFont),
        Encoding: 'Identity-H',
        DescendantFonts: [cid],
        ToUnicode: toUnicode,
      }),
    );
  }
}

function toUnicodeCMap(used: Map<number, string>): string {
  const entries = [...used.entries()].sort((a, b) => a[0] - b[0]);
  const lines: string[] = [];
  for (let i = 0; i < entries.length; i += 100) {
    const chunk = entries.slice(i, i + 100);
    lines.push(`${chunk.length} beginbfchar`);
    for (const [gid, ch] of chunk) {
      const u = Buffer.from(ch, 'utf16le');
      u.swap16();
      lines.push(`<${gid.toString(16).padStart(4, '0')}> <${u.toString('hex')}>`);
    }
    lines.push('endbfchar');
  }
  return [
    '/CIDInit /ProcSet findresource begin',
    '12 dict begin',
    'begincmap',
    '/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def',
    '/CMapName /Adobe-Identity-UCS def',
    '/CMapType 2 def',
    '1 begincodespacerange',
    '<0000> <FFFF>',
    'endcodespacerange',
    ...lines,
    'endcmap',
    'CMapName currentdict /CMap defineresource pop',
    'end',
    'end',
  ].join('\n');
}

