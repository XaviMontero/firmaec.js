/*
 * Copyright (C) 2026
 * Port a TypeScript de FirmaEC firmadigital-libreria.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

import fontkit from '@pdf-lib/fontkit';
import { PDFDocument, PDFFont, PDFName, PDFRef } from 'pdf-lib';
import QRCode from 'qrcode';
import { loadResource } from '../utils/resources.js';

/**
 * Ports of `sign.pdf.appearance.{QrAppereance, Information1Appearance, Information2Appearance}`.
 * The iText layout model (Div + Paragraph with multiplied leading, vertically
 * centered) is reproduced so text lands where the Java library puts it.
 */

export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Font with the metrics iText uses for layout (1000 units, truncated to int). */
export class LayoutFont {
  private readonly widths = new Map<number, number>();

  private constructor(
    readonly pdfFont: PDFFont,
    private readonly fk: any,
    readonly ascent: number,
    readonly descent: number,
  ) {}

  static async embed(doc: PDFDocument, resource: string): Promise<LayoutFont> {
    const bytes = loadResource(resource);
    doc.registerFontkit(fontkit);
    const pdfFont = await doc.embedFont(bytes, { subset: true });
    const fk = (fontkit as any).create(bytes);
    const upm = fk.unitsPerEm;
    const os2 = fk['OS/2'];
    // iText TrueTypeFont: usWinAscent / usWinDescent scaled to 1000 units (int)
    const ascent = Math.trunc((os2.winAscent * 1000) / upm);
    const descent = -Math.trunc((os2.winDescent * 1000) / upm);
    return new LayoutFont(pdfFont, fk, ascent, descent);
  }

  /** Text width in points, iText style (per glyph widths in 1000 units, truncated). */
  width(text: string, size: number): number {
    let w = 0;
    for (const glyph of this.fk.layout(text).glyphs) {
      let gw = this.widths.get(glyph.id);
      if (gw === undefined) {
        gw = Math.trunc((glyph.advanceWidth * 1000) / this.fk.unitsPerEm);
        this.widths.set(glyph.id, gw);
      }
      w += gw;
    }
    return (w * size) / 1000;
  }

  encode(text: string): string {
    return this.pdfFont.encodeText(text).toString();
  }
}

export interface ParagraphSpec {
  text: string;
  font: LayoutFont;
  fontSize: number;
  /** iText `setMultipliedLeading`. */
  leading: number;
}

interface PlacedLine {
  text: string;
  font: LayoutFont;
  fontSize: number;
  x: number;
  y: number;
}

/** iText DefaultSplitCharacters: break after whitespace and '-'. */
function isSplitChar(c: string): boolean {
  return c <= ' ' || c === '-' || c === '‐' || (c >= ' ' && c <= '​');
}

/** Breaks a paragraph into lines that fit `width` (iText TextRenderer behaviour). */
export function breakLines(text: string, font: LayoutFont, size: number, width: number): string[] {
  const lines: string[] = [];
  for (const segment of text.split('\n')) {
    // a trailing newline does not produce an empty line in iText
    if (segment === '' && lines.length > 0 && segment === text.split('\n').at(-1)) continue;
    let rest = segment;
    while (true) {
      if (font.width(rest.replace(/ +$/, ''), size) <= width + 1e-4) {
        lines.push(rest);
        break;
      }
      // longest prefix ending at a split char that fits
      let cut = -1;
      for (let i = 0; i < rest.length; i++) {
        if (isSplitChar(rest[i])) {
          const candidate = rest.substring(0, i + 1);
          if (font.width(candidate.replace(/ +$/, ''), size) <= width + 1e-4) cut = i + 1;
          else break;
        }
      }
      if (cut <= 0) {
        // word longer than the line: split by characters
        cut = 1;
        while (cut < rest.length && font.width(rest.substring(0, cut + 1), size) <= width + 1e-4) cut++;
      }
      lines.push(rest.substring(0, cut));
      rest = rest.substring(cut);
      if (rest === '') break;
    }
  }
  return lines;
}

/**
 * Lays out paragraphs in a Div of the given rect with VerticalAlignment.MIDDLE,
 * HorizontalAlignment.LEFT and zero margins.
 */
export function layoutDiv(paragraphs: ParagraphSpec[], rect: Rect): PlacedLine[] {
  interface Box {
    text: string;
    p: ParagraphSpec;
    height: number;
    topIndent: number;
    ascent: number;
  }
  const boxes: Box[] = [];
  for (const p of paragraphs) {
    const ascent = (p.font.ascent * p.fontSize) / 1000;
    const descent = (p.font.descent * p.fontSize) / 1000;
    const lineHeight = Math.max(p.fontSize, ascent - descent);
    const topIndent = (lineHeight * (p.leading - 1)) / 2;
    for (const text of breakLines(p.text, p.font, p.fontSize, rect.width)) {
      boxes.push({ text, p, height: lineHeight * p.leading, topIndent, ascent });
    }
  }
  const total = boxes.reduce((s, b) => s + b.height, 0);
  let top = rect.y + rect.height;
  if (total <= rect.height) top -= (rect.height - total) / 2;
  const out: PlacedLine[] = [];
  for (const b of boxes) {
    if (top - b.height < rect.y - 1e-4) break; // does not fit: iText drops the overflow
    out.push({
      text: b.text,
      font: b.p.font,
      fontSize: b.p.fontSize,
      x: rect.x,
      y: top - b.topIndent - b.ascent,
    });
    top -= b.height;
  }
  return out;
}

const fmt = (n: number) => {
  const r = Math.round(n * 100) / 100;
  return Object.is(r, -0) ? '0' : String(r);
};

export interface AppearanceStream {
  content: string;
  fonts: Map<string, PDFRef>;
  images: Map<string, PDFRef>;
}

function textOps(lines: PlacedLine[], fontNames: Map<LayoutFont, string>): string {
  return lines
    .map((l) => {
      const text = l.text.replace(/[\n\r]/g, '');
      return `q\nBT\n/${fontNames.get(l.font)} ${fmt(l.fontSize)} Tf\n${fmt(l.x)} ${fmt(l.y)} Td\n${l.font.encode(text)} Tj\nET\nQ\n`;
    })
    .join('');
}

/** Builds the 1-bit image XObject of the QR code (zxing: margin 0, EC level L, US-ASCII). */
export function qrImage(doc: PDFDocument, text: string): { ref: PDFRef; modules: number } {
  // Java encodes with US_ASCII: every non ASCII character becomes '?'
  const ascii = Buffer.from([...text].map((c) => (c.codePointAt(0)! < 0x80 ? c.codePointAt(0)! : 0x3f)));
  const qr = QRCode.create([{ data: ascii, mode: 'byte' }], { errorCorrectionLevel: 'L' });
  const n = qr.modules.size;
  const rowBytes = Math.ceil(n / 8);
  const raw = Buffer.alloc(rowBytes * n);
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      // DeviceGray 1 bit: 0 = black (dark module), 1 = white
      if (!qr.modules.get(y, x)) raw[y * rowBytes + (x >> 3)] |= 0x80 >> (x & 7);
    }
    // padding bits of each row stay as white
    for (let x = n; x < rowBytes * 8; x++) raw[y * rowBytes + (x >> 3)] |= 0x80 >> (x & 7);
  }
  const stream = doc.context.flateStream(raw, {
    Type: 'XObject',
    Subtype: 'Image',
    Width: n,
    Height: n,
    ColorSpace: 'DeviceGray',
    BitsPerComponent: 1,
  });
  return { ref: doc.context.register(stream), modules: n };
}

export interface AppearanceData {
  nombreFirmante: string;
  reason: string | null;
  location: string | null;
  signTime: string | null;
  infoQR?: string;
  informacionCertificado?: string;
}

/** Common interface of the three Java appearances. */
export interface CustomAppearance {
  /** Returns the content stream of layer n2 and its resources. */
  createLayer2(doc: PDFDocument, rect: Rect): Promise<AppearanceStream>;
}

async function fontsFor(doc: PDFDocument, resources: string[]) {
  const fonts = await Promise.all(resources.map((r) => LayoutFont.embed(doc, r)));
  const names = new Map<LayoutFont, string>();
  fonts.forEach((f, i) => names.set(f, 'F' + (i + 1)));
  return { fonts, names };
}

function fontRefs(names: Map<LayoutFont, string>): Map<string, PDFRef> {
  return new Map([...names.entries()].map(([f, n]) => [n, f.pdfFont.ref]));
}

/** Port of `QrAppereance`. */
export class QrAppearance implements CustomAppearance {
  constructor(private readonly d: AppearanceData) {}

  static truncarLinea(linea: string, sufijo: string): string {
    const maxCaracteres = 57;
    if (linea.length > maxCaracteres) return linea.substring(0, maxCaracteres - sufijo.length) + sufijo;
    return linea;
  }

  async createLayer2(doc: PDFDocument, rect: Rect): Promise<AppearanceStream> {
    const { d } = this;
    const { fonts, names } = await fontsFor(doc, ['fonts/courier.ttf', 'fonts/courier-bold.ttf']);
    const [courier, courierBold] = fonts;
    let text = 'FIRMADO POR: ' + d.nombreFirmante.trim() + '\n';
    text += 'RAZON: ' + d.reason + '\n';
    text += 'LOCALIZACION: ' + d.location + '\n';
    text += 'FECHA: ' + d.signTime + '\n';
    text += d.infoQR ?? '';
    const { ref } = qrImage(doc, text);
    const w = rect.width;
    const h = rect.height;
    // Image autoscaled into the full rect, vertically centered, left aligned
    const size = Math.min(w, h);
    let content = `q\n${fmt(size)} 0 0 ${fmt(size)} 0 ${fmt((h - size) / 2)} cm\n/Im1 Do\nQ\n`;
    const textRect: Rect = { x: w / 3, y: 0, width: w - w / 3, height: h };
    const lines = layoutDiv(
      [
        { text: 'Validar únicamente en FirmaEC.\nFirmado electrónicamente por:\n', font: courier, fontSize: 3.25, leading: 1.0 },
        { text: QrAppearance.truncarLinea(d.nombreFirmante, '...').trim(), font: courierBold, fontSize: 6.25, leading: 0.6 },
      ],
      textRect,
    );
    content += textOps(lines, names);
    return { content, fonts: fontRefs(names), images: new Map([['Im1', ref]]) };
  }
}

/** Port of `Information1Appearance`. */
export class Information1Appearance implements CustomAppearance {
  constructor(private readonly d: AppearanceData) {}

  async createLayer2(doc: PDFDocument, rect: Rect): Promise<AppearanceStream> {
    const { d } = this;
    const { fonts, names } = await fontsFor(doc, ['fonts/inter.ttf']);
    const [inter] = fonts;
    const p = (text: string, fontSize: number): ParagraphSpec => ({ text, font: inter, fontSize, leading: 0.9 });
    const lines = layoutDiv(
      [
        p('Firmado electrónicamente por:\n', 2.75),
        p(d.nombreFirmante.trim(), 3.75),
        p('Validar únicamente en FirmaEC', 2.75),
        p('Razón: ' + d.reason, 2.75),
        p('Localización: ' + d.location, 2.75),
        p('Fecha: ' + d.signTime, 2.75),
      ],
      { x: 0, y: 0, width: rect.width, height: rect.height },
    );
    return { content: textOps(lines, names), fonts: fontRefs(names), images: new Map() };
  }
}

/** Port of `Information2Appearance`. */
export class Information2Appearance implements CustomAppearance {
  constructor(private readonly d: AppearanceData) {}

  async createLayer2(doc: PDFDocument, rect: Rect): Promise<AppearanceStream> {
    const { d } = this;
    const { fonts, names } = await fontsFor(doc, ['fonts/inter.ttf']);
    const [inter] = fonts;
    const lines = layoutDiv(
      [
        { text: d.nombreFirmante.trim(), font: inter, fontSize: 4.75, leading: 0.8 },
        { text: 'Validar únicamente en FirmaEC', font: inter, fontSize: 2.75, leading: 0.9 },
        { text: 'Fecha: ' + d.signTime, font: inter, fontSize: 2.75, leading: 0.9 },
        { text: 'Razón: ' + d.reason, font: inter, fontSize: 2.75, leading: 0.9 },
        { text: 'Localización: ' + d.location, font: inter, fontSize: 2.75, leading: 0.9 },
        {
          text: 'Nombre de reconocimiento ' + (d.informacionCertificado ?? '').trim(),
          font: inter,
          fontSize: 2.5,
          leading: 0.8,
        },
      ],
      { x: 0, y: 0, width: rect.width, height: rect.height },
    );
    return { content: textOps(lines, names), fonts: fontRefs(names), images: new Map() };
  }
}

/**
 * Builds the widget appearance with the Acrobat layer structure iText writes:
 * N -> FRM -> (n0 "% DSBlank", n2 custom layer).
 */
export function buildAppearanceXObjects(doc: PDFDocument, rect: Rect, layer2: AppearanceStream | null): PDFRef {
  const ctx = doc.context;
  const bbox = [0, 0, rect.width, rect.height];
  if (!layer2) {
    const empty = ctx.flateStream(Buffer.alloc(0), { Type: 'XObject', Subtype: 'Form', BBox: bbox });
    return ctx.register(empty);
  }
  const fontDict = ctx.obj({});
  for (const [name, ref] of layer2.fonts) fontDict.set(PDFName.of(name), ref);
  const xobjDict = ctx.obj({});
  for (const [name, ref] of layer2.images) xobjDict.set(PDFName.of(name), ref);
  const n2Resources = ctx.obj({});
  if (layer2.fonts.size) n2Resources.set(PDFName.of('Font'), fontDict);
  if (layer2.images.size) n2Resources.set(PDFName.of('XObject'), xobjDict);
  const n2 = ctx.register(
    ctx.flateStream(Buffer.from(layer2.content, 'latin1'), { Type: 'XObject', Subtype: 'Form', BBox: bbox, Resources: n2Resources }),
  );
  const n0 = ctx.register(
    ctx.flateStream(Buffer.from('% DSBlank\n', 'latin1'), { Type: 'XObject', Subtype: 'Form', BBox: bbox, Resources: {} }),
  );
  const frm = ctx.register(
    ctx.flateStream(Buffer.from('q 1 0 0 1 0 0 cm /n0 Do Q\nq 1 0 0 1 0 0 cm /n2 Do Q\n', 'latin1'), {
      Type: 'XObject',
      Subtype: 'Form',
      BBox: bbox,
      Resources: { XObject: { n0, n2 } },
    }),
  );
  return ctx.register(
    ctx.flateStream(Buffer.from('q 1 0 0 1 0 0 cm /FRM Do Q\n', 'latin1'), {
      Type: 'XObject',
      Subtype: 'Form',
      BBox: bbox,
      Resources: { XObject: { FRM: frm } },
    }),
  );
}

