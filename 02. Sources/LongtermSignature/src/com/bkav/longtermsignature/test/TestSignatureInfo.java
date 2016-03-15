package com.bkav.longtermsignature.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackageAccess;
import org.apache.poi.poifs.crypt.dsig.SignatureConfig;
import org.apache.poi.poifs.crypt.dsig.SignatureInfo;
import org.apache.poi.poifs.crypt.dsig.facets.EnvelopedSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.KeyInfoSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.XAdESSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.XAdESXLSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.services.RevocationData;
import org.apache.poi.poifs.crypt.dsig.services.RevocationDataService;
import org.apache.poi.poifs.crypt.dsig.services.TimeStampService;
import org.apache.poi.poifs.crypt.dsig.services.TimeStampServiceValidator;
import org.apache.poi.util.IOUtils;
import org.apache.poi.util.LocaleUtil;
import org.apache.poi.util.POILogFactory;
import org.apache.poi.util.POILogger;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import com.bkav.longtermsignature.cryptotoken.CryptoToken;
import com.bkav.longtermsignature.cryptotoken.CryptoTokenUtil;
import com.bkav.longtermsignature.validationservice.OCSPValidator;

import sun.security.x509.SerialNumber;

public class TestSignatureInfo {
	private static final POILogger LOG = POILogFactory
			.getLogger(TestSignatureInfo.class);

	private static final String INPUT = "S:/WORK/2016/03-2016/Test Files/input.docx";
	private static final String OUTPUT = "S:/WORK/2016/03-2016/Test Files/out.docx";

	public static void main(String[] args) {
		try {
			testSignEnvelopingDocument();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void testSign() {
		String path = "S:/WORK/KEYSTORE/KEY_2048/Server_TuanBS3.p12";
		String pass = "1";
		CryptoTokenUtil tokenUtil = new CryptoTokenUtil();
		CryptoToken token = tokenUtil.initFromPkcs12(path, pass);
		X509Certificate x509 = token.getSignerCert();
		PrivateKey privKey = token.getPrivateKey();

		// filling the SignatureConfig entries (minimum fields, more options are
		// available ...)
		SignatureConfig signatureConfig = new SignatureConfig();
		signatureConfig.setKey(privKey);
		signatureConfig
				.setSigningCertificateChain(Collections.singletonList(x509));
		OPCPackage pkg;
		try {
			pkg = OPCPackage.open(copy(getFile(INPUT)),
					PackageAccess.READ_WRITE);
			signatureConfig.setOpcPackage(pkg);

			// adding the signature document to the package
			SignatureInfo si = new SignatureInfo();
			si.setSignatureConfig(signatureConfig);
			si.confirmSignature();
			pkg.save(new File(OUTPUT));
			pkg.close();
		} catch (InvalidFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (XMLSignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MarshalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void testSignEnvelopingDocument() throws Exception {
		String testFile = INPUT;
		OPCPackage pkg = OPCPackage.open(copy(getFile(testFile)),
				PackageAccess.READ_WRITE);

		String path = "S:/WORK/Keystores/KEY_2048/Server_TuanBS3.p12";
		String pass = "1";

		CryptoTokenUtil tokenUtil = new CryptoTokenUtil();
		CryptoToken token = tokenUtil.initFromPkcs12(path, pass);

		// setup
		SignatureConfig signatureConfig = new SignatureConfig();
		signatureConfig.setOpcPackage(pkg);
		signatureConfig.setKey(token.getPrivateKey());

		// signatureConfig.setSigningCertificateChain(certificateChain);
		signatureConfig.setSigningCertificateChain(
				Collections.singletonList(token.getSignerCert()));

		signatureConfig.addSignatureFacet(new EnvelopedSignatureFacet());
		signatureConfig.addSignatureFacet(new KeyInfoSignatureFacet());
		signatureConfig.addSignatureFacet(new XAdESSignatureFacet());


		// check for internet, no error means it works
		String tsaurl = "http://timestamp.comodoca.com/authenticode";
		boolean mockTsp = (getAccessError(tsaurl, true, 10000) != null);

		signatureConfig.setTspUrl(tsaurl);
		signatureConfig.setTspRequestPolicy(null);
		signatureConfig.setTspOldProtocol(false);

		// set proxy info if any
		String proxy = System.getProperty("http_proxy");
		if (proxy != null && proxy.trim().length() > 0) {
			signatureConfig.setProxyUrl(proxy);
		}

//		if (mockTsp) {
//			System.out.println("TSA Server connect ok");
//			TimeStampService tspService = new TimeStampService() {
//				@Override
//				public byte[] timeStamp(byte[] data,
//						RevocationData revocationData) throws Exception {
//					// revocationData.addCRL(crl);
//					return "time-stamp-token".getBytes(LocaleUtil.CHARSET_1252);
//				}
//
//				@Override
//				public void setSignatureConfig(SignatureConfig config) {
//					// empty on purpose
//				}
//			};
//			signatureConfig.setTspService(tspService);
//		} else {
//			System.out.println("TSA Server connect false");
//			TimeStampServiceValidator tspValidator = new TimeStampServiceValidator() {
//				@Override
//				public void validate(List<X509Certificate> validateChain,
//						RevocationData revocationData) throws Exception {
//					for (X509Certificate certificate : validateChain) {
//						LOG.log(POILogger.DEBUG, "certificate: "
//								+ certificate.getSubjectX500Principal());
//						LOG.log(POILogger.DEBUG,
//								"validity: " + certificate.getNotBefore()
//										+ " - " + certificate.getNotAfter());
//					}
//				}
//			};
//			signatureConfig.setTspValidator(tspValidator);
//			signatureConfig.setTspOldProtocol(
//					signatureConfig.getTspUrl().contains("edelweb"));
//		}

//		signatureConfig.addSignatureFacet(new XAdESXLSignatureFacet());
//		CertificateFactory factory = CertificateFactory.getInstance("X509");
//		X509CRL crl = (X509CRL) factory.generateCRL(
//				new FileInputStream("C:\\BkavCA\\CRLs\\BkavCA.crl"));
//
//		final RevocationData revocationData = new RevocationData();
//		revocationData.addCRL(crl);
//		X509Certificate issuerCert = token.getIssuerCert();
//		BigInteger SerialNumber = token.getSignerCert().getSerialNumber();
//		OCSPReq request = OCSPValidator.generateOCSPReqest(issuerCert, SerialNumber);
//		OCSPResp ocspResp = OCSPValidator.getOCSPResponse("http://ocsp.bkavca.vn", request);
//		System.out.println(ocspResp == null);
//		revocationData.addOCSP(ocspResp.getEncoded());
//
//		RevocationDataService revocationDataService = new RevocationDataService() {
//			@Override
//			public RevocationData getRevocationData(
//					List<X509Certificate> revocationChain) {
//				return revocationData;
//			}
//		};
//		signatureConfig.setRevocationDataService(revocationDataService);

		// operate
		SignatureInfo si = new SignatureInfo();
		si.setSignatureConfig(signatureConfig);
		try {
			si.confirmSignature();
		} catch (RuntimeException e) {
			pkg.close();
			if (e.getCause() == null) {
				throw e;
			}
			if (!(e.getCause() instanceof ConnectException)) {
				throw e;
			}
		}

		pkg.save(new File(OUTPUT));

		pkg.close();
	}

	public static String getAccessError(String destinationUrl,
			boolean fireRequest, int timeout) {
		URL url;
		try {
			url = new URL(destinationUrl);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid destination URL", e);
		}

		HttpURLConnection conn = null;
		try {
			conn = (HttpURLConnection) url.openConnection();

			// set specified timeout if non-zero
			if (timeout != 0) {
				conn.setConnectTimeout(timeout);
				conn.setReadTimeout(timeout);
			}

			conn.setDoOutput(false);
			conn.setDoInput(true);

			/*
			 * if connecting is not possible this will throw a connection
			 * refused exception
			 */
			conn.connect();

			if (fireRequest) {
				InputStream is = null;
				try {
					is = conn.getInputStream();
				} finally {
					IOUtils.closeQuietly(is);
				}

			}
			/* if connecting is possible we return true here */
			return null;

		} catch (IOException e) {
			/* exception is thrown -> server not available */
			return e.getClass().getName() + ": " + e.getMessage();
		} finally {
			if (conn != null) {
				conn.disconnect();
			}
		}
	}

	public static File copy(File input) throws IOException {
		String extension = input.getName().replaceAll(".*?(\\.[^.]+)?$", "$1");
		if (extension == null || "".equals(extension)) {
			extension = ".zip";
		}

		File buildDir = new File("build");
		if (!buildDir.exists()) {
			assertTrue("Failed to create " + buildDir.getAbsolutePath(),
					buildDir.mkdirs());
		}
		File tmpFile = new File(buildDir, "sigtest" + extension);

		OutputStream fos = new FileOutputStream(tmpFile);
		try {
			InputStream fis = new FileInputStream(input);
			try {
				IOUtils.copy(fis, fos);
			} finally {
				fis.close();
			}
		} finally {
			fos.close();
		}

		return tmpFile;
	}

	private static File getFile(String inputDir) {
		return new File(inputDir);
	}

}