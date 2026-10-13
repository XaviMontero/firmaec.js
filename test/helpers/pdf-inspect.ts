/** Structural inspection of signed PDFs, used to compare Java (iText) and TS output. */
import zlib from 'node:zlib';
import jsQR from 'jsqr';
import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFHexString,
  PDFName,
  PDFNumber,
  PDFRawStream,
  PDFRef,
  PDFStream,
  PDFString,
} from 'pdf-lib';

export interface TextLine {
  font: string;
  size: number;
  x: number;
  y: number;
  /** Concatenated glyph ids (hex), trailing spaces removed. */
  glyphs: string;
}

export interface SignatureField {
  name: string;
  page: number;
  rect: number[];
  flags: number | null;
  fieldType: string | null;
  dict: Record<string, string | null>;
  text: TextLine[];
  images: Array<{ width: number; height: number; matrix: number[] }>;
  qr: string | null;
}

function str(v: unknown): string | null {
  if (v instanceof PDFString || v instanceof PDFHexString) return v.decodeText();
  if (v instanceof PDFName) return v.decodeText();
  if (v === undefined || v === null) return null;
  return String(v);
}

function streamBytes(s: PDFStream): Buffer {
  const raw = Buffer.from((s as PDFRawStream).contents ?? (s as any).getContents());
  const filter = s.dict.get(PDFName.of('Filter'));
  return filter && filter.toString() === '/FlateDecode' ? zlib.inflateSync(raw) : raw;
}

export async function inspectSignatures(bytes: Uint8Array): Promise<SignatureField[]> {
  const doc = await PDFDocument.load(bytes, { updateMetadata: false });
  const ctx = doc.context;
  const pages = doc.getPages();
  const acro = ctx.lookupMaybe(doc.catalog.get(PDFName.of('AcroForm')), PDFDict);
  const fields = acro ? ctx.lookupMaybe(acro.get(PDFName.of('Fields')), PDFArray) : undefined;
  const out: SignatureField[] = [];
  if (!fields) return out;
  for (let i = 0; i < fields.size(); i++) {
    const f = ctx.lookup(fields.get(i), PDFDict);
    if (f.get(PDFName.of('FT'))?.toString() !== '/Sig') continue;
    const v = ctx.lookupMaybe(f.get(PDFName.of('V')), PDFDict);
    const dict: Record<string, string | null> = {};
    if (v) {
      for (const key of ['Filter', 'SubFilter', 'Reason', 'Location', 'ContactInfo', 'M', 'Type', 'Name']) {
        dict[key] = str(v.get(PDFName.of(key)));
      }
      const pb = ctx.lookupMaybe(v.get(PDFName.of('Prop_Build')), PDFDict);
      const app = pb ? ctx.lookupMaybe(pb.get(PDFName.of('App')), PDFDict) : undefined;
      dict['Prop_Build.App.Name'] = app ? str(app.get(PDFName.of('Name'))) : null;
    }
    const pRef = f.get(PDFName.of('P'));
    const page = pages.findIndex((p) => pRef instanceof PDFRef && p.ref === pRef) + 1;
    const rect = (ctx.lookup(f.get(PDFName.of('Rect')), PDFArray).asArray() as PDFNumber[]).map((n) => n.asNumber());
    const field: SignatureField = {
      name: str(f.get(PDFName.of('T')))!,
      page,
      rect,
      flags: (f.get(PDFName.of('F')) as PDFNumber | undefined)?.asNumber() ?? null,
      fieldType: str(f.get(PDFName.of('FT'))),
      dict,
      text: [],
      images: [],
      qr: null,
    };
    // appearance: N -> FRM -> n2
    const ap = ctx.lookupMaybe(f.get(PDFName.of('AP')), PDFDict);
    const n = ap ? ctx.lookupMaybe(ap.get(PDFName.of('N')), PDFStream) : undefined;
    const n2 = n ? findLayer2(ctx, n) : undefined;
    if (n2) parseLayer(ctx, n2, field);
    out.push(field);
  }
  return out;
}

function xobjects(ctx: PDFDocument['context'], s: PDFStream): PDFDict | undefined {
  const res = ctx.lookupMaybe(s.dict.get(PDFName.of('Resources')), PDFDict);
  return res ? ctx.lookupMaybe(res.get(PDFName.of('XObject')), PDFDict) : undefined;
}

function findLayer2(ctx: PDFDocument['context'], n: PDFStream): PDFStream | undefined {
  const frm = xobjects(ctx, n)?.get(PDFName.of('FRM'));
  const frmStream = frm ? ctx.lookupMaybe(frm, PDFStream) : undefined;
  const n2 = frmStream ? xobjects(ctx, frmStream)?.get(PDFName.of('n2')) : undefined;
  return n2 ? ctx.lookupMaybe(n2, PDFStream) : undefined;
}

function parseLayer(ctx: PDFDocument['context'], n2: PDFStream, field: SignatureField) {
  const res = ctx.lookup(n2.dict.get(PDFName.of('Resources')), PDFDict);
  const fonts = ctx.lookupMaybe(res.get(PDFName.of('Font')), PDFDict);
  const xobj = ctx.lookupMaybe(res.get(PDFName.of('XObject')), PDFDict);
  const content = streamBytes(n2).toString('latin1');
  const tokens = content.match(/<[0-9a-fA-F]*>|\/[^\s/<>[\]()]+|[-+]?\d*\.?\d+|[A-Za-z*'"]+/g) ?? [];
  const stack: string[] = [];
  let font = '';
  let size = 0;
  let pos: [number, number] = [0, 0];
  let current: TextLine | null = null;
  let cm: number[] = [1, 0, 0, 1, 0, 0];
  for (const t of tokens) {
    switch (t) {
      case 'BT':
        current = null;
        break;
      case 'Tf': {
        size = parseFloat(stack.pop()!);
        const name = stack.pop()!.substring(1);
        const fontDict = fonts ? ctx.lookup(fonts.get(PDFName.of(name)), PDFDict) : undefined;
        font = (fontDict?.get(PDFName.of('BaseFont'))?.toString() ?? name).replace(/^\/[A-Z]{6}\+/, '');
        break;
      }
      case 'Td': {
        const y = parseFloat(stack.pop()!);
        const x = parseFloat(stack.pop()!);
        pos = [x, y];
        break;
      }
      case 'Tj': {
        const hex = stack.pop()!.slice(1, -1).toLowerCase();
        if (!current) {
          current = { font, size, x: pos[0], y: pos[1], glyphs: '' };
          field.text.push(current);
        }
        current.glyphs += hex;
        break;
      }
      case 'ET':
        if (current) current.glyphs = current.glyphs.replace(/(0003)+$/, '');
        current = null;
        break;
      case 'cm':
        cm = stack.splice(-6).map(parseFloat);
        break;
      case 'Do': {
        const name = stack.pop()!.substring(1);
        const img = xobj ? ctx.lookup(xobj.get(PDFName.of(name)), PDFStream) : undefined;
        if (img && img.dict.get(PDFName.of('Subtype'))?.toString() === '/Image') {
          const w = (img.dict.get(PDFName.of('Width')) as PDFNumber).asNumber();
          const h = (img.dict.get(PDFName.of('Height')) as PDFNumber).asNumber();
          field.images.push({ width: w, height: h, matrix: cm });
          field.qr = decodeQrImage(img, w, h);
        }
        break;
      }
      default:
        stack.push(t);
    }
  }
}

/** Decodes a 1-bit DeviceGray image (optionally PNG-predicted) with jsQR. */
function decodeQrImage(img: PDFStream, w: number, h: number): string | null {
  let data = streamBytes(img);
  const rowBytes = Math.ceil(w / 8);
  const parms = img.dict.get(PDFName.of('DecodeParms'));
  if (parms instanceof PDFDict && (parms.get(PDFName.of('Predictor')) as PDFNumber)?.asNumber() >= 10) {
    const out = Buffer.alloc(rowBytes * h);
    let prev = Buffer.alloc(rowBytes);
    for (let y = 0; y < h; y++) {
      const filter = data[y * (rowBytes + 1)];
      const row = Buffer.from(data.subarray(y * (rowBytes + 1) + 1, (y + 1) * (rowBytes + 1)));
      for (let i = 0; i < rowBytes; i++) {
        const left = i > 0 ? row[i - 1] : 0;
        const up = prev[i];
        const ul = i > 0 ? prev[i - 1] : 0;
        if (filter === 1) row[i] = (row[i] + left) & 0xff;
        else if (filter === 2) row[i] = (row[i] + up) & 0xff;
        else if (filter === 3) row[i] = (row[i] + ((left + up) >> 1)) & 0xff;
        else if (filter === 4) {
          const p = left + up - ul;
          const pa = Math.abs(p - left);
          const pb = Math.abs(p - up);
          const pc = Math.abs(p - ul);
          row[i] = (row[i] + (pa <= pb && pa <= pc ? left : pb <= pc ? up : ul)) & 0xff;
        }
      }
      row.copy(out, y * rowBytes);
      prev = row;
    }
    data = out;
  }
  // render with a 4 module quiet zone, 4x scale
  const scale = 4;
  const border = 4;
  const W = (w + border * 2) * scale;
  const H = (h + border * 2) * scale;
  const rgba = new Uint8ClampedArray(W * H * 4).fill(255);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const bit = (data[y * rowBytes + (x >> 3)] >> (7 - (x & 7))) & 1;
      if (bit === 0) {
        for (let dy = 0; dy < scale; dy++) {
          for (let dx = 0; dx < scale; dx++) {
            const p = ((y + border) * scale + dy) * W + (x + border) * scale + dx;
            rgba[p * 4] = rgba[p * 4 + 1] = rgba[p * 4 + 2] = 0;
          }
        }
      }
    }
  }
  return jsQR(rgba, W, H)?.data ?? null;
}
