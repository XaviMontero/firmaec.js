# firmadigital-libreria-js

Port a TypeScript/Node.js de [FirmaEC `firmadigital-libreria`](https://minka.gob.ec/mintel/ge/firmaec/firmadigital-libreria) (MINTEL, Ecuador), versión 5.2.0, commit `014b327`. Firma documentos con un archivo `.p12`/`.pfx` sin depender de Java.

| Funcionalidad | Clase Java original | En este port |
|---|---|---|
| Firma de PDF PAdES (`adbe.pkcs7.detached`), modo incremental | `PadesBasicSigner` | `PadesBasicSigner`, `firmarPdf()` |
| Firma de PDF con sello de tiempo RFC 3161 | `PadesEnhancedSigner` | `PadesEnhancedSigner`, `firmarPdf(..., { selloTiempo: true })` |
| Firma visible: `QR`, `information1`, `information2` | `QrAppereance`, `Information1/2Appearance` | igual, con el mismo layout que iText |
| Firma XML XAdES-BES (SRI, nodo `#comprobante`) | `XAdESSigner` (EU DSS) | `XAdESSigner`, `firmarXml()` |
| Datos del firmante de las 17 CA ecuatorianas | `CertEcUtils.getDatosUsuarios` | `getDatosUsuarios()` |
| Lectura de `.p12` (incluye 3DES/RC2 legacy) | `KeyStore` PKCS12 | `KeyStore.fromPkcs12()` |

Requiere Node.js 18 o superior. Dependencias de runtime: `node-forge`, `pdf-lib`, `qrcode`, `@xmldom/xmldom` y `xml-crypto`.

## Uso

```ts
import fs from 'node:fs';
import { firmarPdf, firmarXml } from 'firmadigital-libreria-js';

const p12 = fs.readFileSync('firma.p12');

// PDF con firma visible QR (mismas propiedades que la librería Java)
const pdf = await firmarPdf(fs.readFileSync('contrato.pdf'), p12, 'clave', {
  signingReason: 'Aprobación',
  signingLocation: 'Quito',
  signTime: '2026-10-12T10:15:30-05:00', // ISO-8601 con offset
  page: 1,                                // 0, fuera de rango o ausente = última página
  typeSignature: 'QR',                    // 'QR' | 'information1' | 'information2' | ausente = invisible
  infoQR: 'Validar en https://www.firmadigital.gob.ec',
  PositionOnPageLowerLeftX: 100,
  PositionOnPageLowerLeftY: 150,
  // PositionOnPageUpperRightX / Y: igual que en Java, son ANCHO y ALTO (no coordenadas)
});
fs.writeFileSync('contrato-firmado.pdf', pdf);

// PDF con sello de tiempo: usuario y clave de la TSA = identificacion (como FirmaEC)
await firmarPdf(pdfBytes, p12, 'clave', { identificacion: '1712345678' }, { selloTiempo: true });

// Comprobante electrónico del SRI (XAdES-BES enveloped sobre id="comprobante")
const xml = await firmarXml(fs.readFileSync('factura.xml'), p12, 'clave');
```

Las clases con los nombres de Java también se exportan:

```ts
import { KeyStore, PadesBasicSigner, XAdESSigner, getDatosUsuarios } from 'firmadigital-libreria-js';

const entry = KeyStore.fromPkcs12(p12, 'clave').getEntry(); // o getEntry(alias), getSigningAliases()
const firmado = await new PadesBasicSigner().sign(pdfBytes, entry.privateKey, entry.chain, propiedades);
const datos = getDatosUsuarios(entry.certificate); // cédula, nombre, apellido, RUC, razón social, cargo...
```

## Cómo se verificó

Los tests de la librería Java no se pueden ejecutar: tienen el `@Test` comentado y leen archivos de la máquina del autor (`/home/mfernandez/Test/Verify/...`). Por eso la suite de este repo usa la librería Java original como **oráculo**. `scripts/setup-oracle.sh` la clona, la compila y la expone con `oracle/Oracle.java`. Cada caso se ejecuta en Java y en TS con las mismas entradas y se comparan los resultados:

- **Datos del firmante** (17 CA, todas las ramas de detección, campos en extensiones, subject y `otherName` del SAN, tipos de string ASN.1, casos sin datos): mismo JSON que Java.
- **PDF**: iText valida la firma TS (integridad y cobertura de todo el documento). También la validan poppler (`pdfsig`) y `qpdf --check`. Se comparan entre Java y TS:
  - el diccionario de firma y el widget;
  - la capa visible: cada línea de texto, con fuente, tamaño, glifos y posición al centésimo de punto;
  - el contenido decodificado del QR.

  Se prueba con PDFs con xref clásico, con object streams y con AcroForm existente, y con firmas múltiples alternando Java y TS. El contenedor CMS sale byte a byte idéntico al de iText.
- **Sello de tiempo**: una TSA local (`openssl ts`) con autenticación básica. iText verifica el token, y los mensajes de error (401 y otros códigos HTTP) son los mismos que en Java.
- **XML**: DSS valida la firma TS (`XAdES-BASELINE-B`, firma íntegra, referencias intactas) y xmlsec1 también. El documento serializado sale byte a byte igual que el de DSS: orden de atributos, declaración y codificación ISO-8859-1. La estructura de la firma es la misma.
- **Errores**: los casos en que Java falla (posición inválida, CA desconocida con firma visible, `typeSignature` inválido, falta `#comprobante`, DOCTYPE, XML mal formado) también fallan en TS.

```bash
npm install
npm run setup:oracle   # requiere git, JDK 17+ y Maven (solo para los tests)
npm test               # 106 tests (paridad con Java + e2e)
npm run test:unit      # sin oráculo
```

## Diferencias conocidas y lo que no se portó

- **No portado:** verificación de documentos (`Utils.verificarDocumento`), OCSP/CRL, `PadesLtvSigner`, tokens PKCS#11 (ePass, SafeNet, Bit4id…) y los keystores de Windows/macOS.
- **Claves EC:** la librería Java falla con `Unsupported algorithm: EC`. Este port también firma con claves EC (ECDSA), y iText y DSS validan esas firmas.
- **QR:** zxing agrega un segmento ECI (US-ASCII) y `qrcode` no, así que la matriz puede variar. El texto decodificado es idéntico, y los caracteres no ASCII se reemplazan por `?` igual que en Java.
- **Diccionario `/Info` del PDF:** iText reescribe `/Producer` y `/ModDate` con su propia marca. Este port no modifica `/Info`.
- **CA no reconocida con firma visible:** Java lanza un `NullPointerException`. Aquí se lanza `EntidadCertificadoraNoValidaException` con un mensaje claro. La firma invisible funciona igual en ambos.
- **`X500Principal.getName()`:** se usa la semántica de JDK 21, que decodifica BMPString y T61String correctamente. Solo afecta el texto "Entidad no reconocida …".
- Se mantienen a propósito las rarezas del original:
  - `UpperRightX/Y` son ancho y alto;
  - DIGERCIC usa el parser de Datil;
  - las etiquetas de tipo de certificado conservan sus inconsistencias de tildes;
  - un nombre vacío no ocupa línea en la firma visible.

## Licencia

AGPL-3.0-or-later, igual que el original (es obra derivada). Si se usa en un servicio accesible por red, hay que ofrecer el código fuente a sus usuarios.
