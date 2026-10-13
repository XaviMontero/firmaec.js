import { describe, expect, it } from 'vitest';
import { getPositionOnPage } from '../../src/pdf/pades-signer.js';
import { pdfDate, pdfTextString } from '../../src/pdf/pdf-strings.js';
import { parseJavaInt, parseSignTime } from '../../src/utils/properties.js';

describe('RectanguloUtil.getPositionOnPage', () => {
  it('uses UpperRight values as width/height (iText Rectangle)', () => {
    expect(getPositionOnPage({ PositionOnPageLowerLeftX: '50', PositionOnPageLowerLeftY: '700', PositionOnPageUpperRightX: '250', PositionOnPageUpperRightY: '60' })).toEqual({ x: 50, y: 700, width: 250, height: 60 });
  });
  it('defaults to 110x36 below the point', () => {
    expect(getPositionOnPage({ PositionOnPageLowerLeftX: ' 100 ', PositionOnPageLowerLeftY: '150' })).toEqual({ x: 100, y: 114, width: 110, height: 36 });
  });
  it('returns null for decimals, partial or missing values', () => {
    expect(getPositionOnPage({ PositionOnPageLowerLeftX: '10.5', PositionOnPageLowerLeftY: '150' })).toBeNull();
    expect(getPositionOnPage({ PositionOnPageLowerLeftX: '10', PositionOnPageLowerLeftY: '1', PositionOnPageUpperRightX: '5' })).toBeNull();
    expect(getPositionOnPage({})).toBeNull();
  });
});

describe('Java parsing helpers', () => {
  it('Integer.parseInt', () => {
    expect(parseJavaInt('+12')).toBe(12);
    expect(parseJavaInt('-3')).toBe(-3);
    expect(() => parseJavaInt('1e3')).toThrow();
    expect(() => parseJavaInt('2147483648')).toThrow();
  });
  it('ISO_OFFSET_DATE_TIME', () => {
    expect(parseSignTime('2026-10-12T10:15:30-05:00')?.toISOString()).toBe('2026-10-12T15:15:30.000Z');
    expect(parseSignTime('2026-10-12T10:15Z')?.toISOString()).toBe('2026-10-12T10:15:00.000Z');
    expect(parseSignTime('2026-10-12T10:15:30.123456+01:30')?.toISOString()).toBe('2026-10-12T08:45:30.123Z');
    expect(parseSignTime('2026-10-12 10:15:30')).toBeNull();
    expect(parseSignTime('2026-02-30T10:15:30Z')).toBeNull();
    expect(parseSignTime('2026-10-12T10:15:30')).toBeNull();
  });
});

describe('PDF strings like iText', () => {
  it('PdfDate', () => {
    const d = new Date('2026-10-12T15:15:30Z');
    expect(pdfDate(d, -300)).toBe("D:20261012101530-05'00'");
    expect(pdfDate(d, 0)).toBe('D:20261012151530Z');
    expect(pdfDate(d, 330)).toBe("D:20261012204530+05'30'");
  });
  it('text strings: PDFDocEncoding when possible, UTF-16BE otherwise', () => {
    expect(pdfTextString('Quito (Ecuador) \\ ñ')).toBe('(Quito \\(Ecuador\\) \\\\ ñ)');
    expect(pdfTextString('€ • —')).toBe('(  \u0080 \u0084)');
    expect(pdfTextString('Firma ✓')).toBe('<FEFF004600690072006D00612000002713>'.replace('2000002713', '00202713'));
  });
});
