import ec.gob.firmadigital.libreria.certificate.CertEcUtils;
import ec.gob.firmadigital.libreria.certificate.to.DatosUsuario;
import ec.gob.firmadigital.libreria.sign.DigestAlgorithm;
import ec.gob.firmadigital.libreria.sign.PrivateKeySigner;
import ec.gob.firmadigital.libreria.sign.SignInfo;
import ec.gob.firmadigital.libreria.sign.pdf.PadesBasicSigner;
import ec.gob.firmadigital.libreria.sign.xades.XAdESSigner;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;

/**
 * Oracle CLI over the original Java FirmaEC library. Used by the JS e2e tests to
 * cross-check behaviour. Every command prints a single JSON document to stdout.
 */
public class Oracle {

    public static void main(String[] args) throws Exception {
        java.util.logging.LogManager.getLogManager().reset();
        switch (args[0]) {
            case "sign-pdf" -> signPdf(args[1], args[2], args[3], args[4], args.length > 5 ? args[5] : null);
            case "sign-xml" -> signXml(args[1], args[2], args[3], args[4]);
            case "datos" -> {
                StringBuilder sb = new StringBuilder("[");
                for (int i = 1; i < args.length; i++) sb.append(i > 1 ? "," : "").append(datos(args[i]));
                System.out.println(sb.append("]"));
            }
            case "x500" -> {
                StringBuilder sb = new StringBuilder("[");
                for (int i = 1; i < args.length; i++) sb.append(i > 1 ? "," : "").append(x500(args[i]));
                System.out.println(sb.append("]"));
            }
            case "verify-pdf" -> verifyPdf(args[1]);
            case "verify-xml" -> verifyXml(args[1], args.length > 2 ? args[2] : null);
            default -> throw new IllegalArgumentException(args[0]);
        }
    }

    record Entry(PrivateKey key, Certificate[] chain) {}

    static Entry load(String p12, String pass) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(p12)) {
            ks.load(in, pass.toCharArray());
        }
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) {
                return new Entry((PrivateKey) ks.getKey(a, pass.toCharArray()), ks.getCertificateChain(a));
            }
        }
        throw new IllegalStateException("no key entry");
    }

    static void signPdf(String p12, String pass, String in, String out, String propsFile) throws Exception {
        Entry e = load(p12, pass);
        Properties props = new Properties();
        if (propsFile != null) {
            try (FileInputStream pin = new FileInputStream(propsFile)) {
                props.load(new java.io.InputStreamReader(pin, java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        PadesBasicSigner signer = new PadesBasicSigner(new PrivateKeySigner(e.key(), DigestAlgorithm.SHA256));
        byte[] signed = signer.sign(new ByteArrayInputStream(Files.readAllBytes(Path.of(in))), e.key(), e.chain(), props);
        Files.write(Path.of(out), signed);
        System.out.println("{\"ok\":true}");
    }

    static void signXml(String p12, String pass, String in, String out) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fin = new FileInputStream(p12)) {
            ks.load(fin, pass.toCharArray());
        }
        byte[] signed = new XAdESSigner().sign(Files.readAllBytes(Path.of(in)), ks, pass.toCharArray());
        Files.write(Path.of(out), signed);
        System.out.println("{\"ok\":true}");
    }

    static X509Certificate readCert(String path) throws Exception {
        try (FileInputStream in = new FileInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    static String x500(String certPath) throws Exception {
        X509Certificate cert = readCert(certPath);
        return "{\"issuer\":" + q(cert.getIssuerX500Principal().toString())
                + ",\"issuerRfc2253\":" + q(cert.getIssuerX500Principal().getName())
                + ",\"subject\":" + q(cert.getSubjectX500Principal().toString())
                + ",\"cn\":" + q(ec.gob.firmadigital.libreria.core.Util.getCN(cert))
                + ",\"email\":" + q(ec.gob.firmadigital.libreria.utils.CertificateUtils.getEmail(cert))
                + "}";
    }

    static String datos(String certPath) throws Exception {
        X509Certificate cert = readCert(certPath);
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"entidad\":").append(q(CertEcUtils.getNombreCA(cert)));
        try {
            DatosUsuario d = CertEcUtils.getDatosUsuarios(cert);
            if (d == null) {
                sb.append(",\"datos\":null");
            } else {
                sb.append(",\"datos\":{")
                        .append("\"tipoCertificado\":").append(q(d.getTipoCertificado()))
                        .append(",\"cedula\":").append(q(d.getCedula()))
                        .append(",\"nombre\":").append(q(d.getNombre()))
                        .append(",\"apellido\":").append(q(d.getApellido()))
                        .append(",\"ruc\":").append(q(d.getRuc()))
                        .append(",\"razonSocial\":").append(q(d.getRazonSocial()))
                        .append(",\"institucion\":").append(q(d.getInstitucion()))
                        .append(",\"cargo\":").append(q(d.getCargo()))
                        .append(",\"commonName\":").append(q(d.getCommonName()))
                        .append(",\"email\":").append(q(d.getEmail()))
                        .append(",\"certificadoDigitalValido\":").append(d.isCertificadoDigitalValido())
                        .append("}");
            }
        } catch (Exception ex) {
            sb.append(",\"error\":").append(q(ex.getClass().getSimpleName() + ": " + ex.getMessage()));
        }
        return sb.append("}").toString();
    }

    static void verifyPdf(String path) throws Exception {
        try (PdfDocument doc = new PdfDocument(new PdfReader(path))) {
            SignatureUtil su = new SignatureUtil(doc);
            List<String> names = su.getSignatureNames();
            SimpleDateFormat iso = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            iso.setTimeZone(TimeZone.getTimeZone("UTC"));
            StringBuilder sb = new StringBuilder("{\"signatures\":[");
            for (int i = 0; i < names.size(); i++) {
                String n = names.get(i);
                PdfPKCS7 p7 = su.readSignatureData(n);
                if (i > 0) sb.append(',');
                sb.append("{\"name\":").append(q(n))
                        .append(",\"integrity\":").append(p7.verifySignatureIntegrityAndAuthenticity())
                        .append(",\"coversWholeDocument\":").append(su.signatureCoversWholeDocument(n))
                        .append(",\"revision\":").append(su.getRevision(n))
                        .append(",\"signer\":").append(q(p7.getSigningCertificate().getSubjectX500Principal().getName()))
                        .append(",\"chainLength\":").append(p7.getSignCertificateChain().length)
                        .append(",\"digestAlgorithm\":").append(q(p7.getDigestAlgorithmName()))
                        .append(",\"signDate\":").append(q(iso.format(p7.getSignDate().getTime())))
                        .append(",\"reason\":").append(q(p7.getReason()))
                        .append(",\"location\":").append(q(p7.getLocation()))
                        .append(",\"filter\":").append(q(String.valueOf(p7.getFilterSubtype())))
                        .append('}');
            }
            sb.append("],\"pages\":").append(doc.getNumberOfPages());
            List<SignInfo> infos = new PadesBasicSigner(null).getSigners(Files.readAllBytes(Path.of(path)));
            sb.append(",\"rubricaSigners\":").append(infos.size()).append('}');
            System.out.println(sb);
        }
    }

    static void verifyXml(String path, String trustedCa) throws Exception {
        DSSDocument doc = new InMemoryDocument(Files.readAllBytes(Path.of(path)));
        SignedDocumentValidator v = SignedDocumentValidator.fromDocument(doc);
        CommonCertificateVerifier cv = new CommonCertificateVerifier();
        if (trustedCa != null) {
            CommonTrustedCertificateSource ts = new CommonTrustedCertificateSource();
            ts.addCertificate(new CertificateToken(readCert(trustedCa)));
            cv.setTrustedCertSources(ts);
        }
        v.setCertificateVerifier(cv);
        Reports reports = v.validateDocument();
        DiagnosticData dd = reports.getDiagnosticData();
        StringBuilder sb = new StringBuilder("{\"signatures\":[");
        List<SignatureWrapper> sigs = dd.getSignatures();
        for (int i = 0; i < sigs.size(); i++) {
            SignatureWrapper s = sigs.get(i);
            if (i > 0) sb.append(',');
            List<String> matchers = new ArrayList<>();
            for (XmlDigestMatcher m : s.getDigestMatchers()) {
                matchers.add("{\"type\":" + q(String.valueOf(m.getType())) + ",\"found\":" + m.isDataFound() + ",\"intact\":" + m.isDataIntact() + "}");
            }
            sb.append("{\"format\":").append(q(String.valueOf(s.getSignatureFormat())))
                    .append(",\"signatureIntact\":").append(s.isSignatureIntact())
                    .append(",\"signatureValid\":").append(s.isSignatureValid())
                    .append(",\"signingCertificatePresent\":").append(s.isSigningCertificateIdentified())
                    .append(",\"indication\":").append(q(String.valueOf(reports.getSimpleReport().getIndication(s.getId()))))
                    .append(",\"subIndication\":").append(q(String.valueOf(reports.getSimpleReport().getSubIndication(s.getId()))))
                    .append(",\"digestMatchers\":").append(matchers)
                    .append('}');
        }
        List<SignInfo> infos = new XAdESSigner().getSignInfo(Files.readAllBytes(Path.of(path)));
        sb.append("],\"rubricaSigners\":").append(infos.size()).append('}');
        System.out.println(sb);
    }

    static String q(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }
}
