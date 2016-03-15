package com.bkav.longtermsignature.cryptotoken;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.log4j.Logger;

public class CryptoTokenUtil implements ICryptoTokenUtil {
	// Logger for CryptotokenUtil class
	private static final Logger LOG = Logger.getLogger(CryptoToken.class);
	// Default keystore type
	private static final String PKCS12 = "PKCS12";
	private static final String PKCS11 = "PKCS11";
	private static final String WINDOWS_MY = "Windows-MY";

	public CryptoToken initFromPkcs12(String keystorePath,
			String keystorePass) {
		CryptoToken result = null;

		try {
			KeyStore keystore = KeyStore.getInstance(PKCS12);
			FileInputStream inStream = new FileInputStream(
					new File(keystorePath));
			keystore.load(inStream, keystorePass.toCharArray());

			Enumeration<String> aliases = keystore.aliases();
			String signerAlias = null;
			PrivateKey signerPrivateKey = null;
			Provider privateKeyProvider = null;
			X509Certificate signerCert = null;
			X509Certificate issuerCert = null;
			Certificate[] chain = null;

			// Tim signer's alias
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				Key key = keystore.getKey(alias, keystorePass.toCharArray());
				if (key != null) {
					signerAlias = alias;
					signerPrivateKey = (PrivateKey) key;
					privateKeyProvider = keystore.getProvider();
					break;
				}
			}

			if (signerAlias != null) {
				Certificate cert = keystore.getCertificate(signerAlias);
				if (cert instanceof X509Certificate) {
					signerCert = (X509Certificate) cert;
				}

				chain = keystore.getCertificateChain(signerAlias);

				// Tim issuer certificate tu certchain
				issuerCert = getIssuerCertFromChain(signerCert, chain);

				result = new CryptoToken(signerPrivateKey, signerCert,
						issuerCert, chain, privateKeyProvider);
			}
		} catch (KeyStoreException e) {
			LOG.error("KeyStoreException: " + e.getMessage());
		} catch (FileNotFoundException e) {
			LOG.error("FileNotFoundException: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			LOG.error("FileNotFoundException: " + e.getMessage());
		} catch (CertificateException e) {
			LOG.error("FileNotFoundException: " + e.getMessage());
		} catch (IOException e) {
			LOG.error("FileNotFoundException: " + e.getMessage());
		} catch (UnrecoverableKeyException e) {
			LOG.error("FileNotFoundException: " + e.getMessage());
		}

		return result;
	}

	@Override
	public CryptoToken initFromCSP(String serialNumber) {
		CryptoToken result = null;
		KeyStore ks;
		try {
			ks = KeyStore.getInstance(WINDOWS_MY);
			ks.load(null, null);

			String signerAlias = null;
			PrivateKey signerPrivateKey = null;
			Provider privateKeyProvider = null;
			X509Certificate signerCert = null;
			X509Certificate issuerCert = null;
			Certificate[] chain = null;

			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = (String) aliases.nextElement();
				if (ks.isKeyEntry(alias)) {
					Certificate cert = ks.getCertificate(alias);
					if (cert instanceof X509Certificate) {
						X509Certificate x509Cert = (X509Certificate) cert;
						if (x509Cert.getSerialNumber().toString(10)
								.equals(serialNumber)) {
							signerCert = x509Cert;
							signerAlias = alias;
							break;
						}
					}
				}
			}

			if (signerAlias != null) {
				Key key = ks.getKey(signerAlias, null);
				if (key instanceof PrivateKey) {
					signerPrivateKey = (PrivateKey) key;
				}

				privateKeyProvider = ks.getProvider();
				chain = ks.getCertificateChain(signerAlias);

				// Tim issuer certificate tu certchain
				issuerCert = getIssuerCertFromChain(signerCert, chain);

				result = new CryptoToken(signerPrivateKey, signerCert,
						issuerCert, chain, privateKeyProvider);
			}
		} catch (KeyStoreException e) {
			LOG.error("KeyStoreException: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			LOG.error("NoSuchAlgorithmException: " + e.getMessage());
		} catch (CertificateException e) {
			LOG.error("CertificateException: " + e.getMessage());
		} catch (IOException e) {
			LOG.error("IOException: " + e.getMessage());
		} catch (UnrecoverableKeyException e) {
			LOG.error("UnrecoverableKeyException: " + e.getMessage());
		}

		return result;
	}

	@Override
	public CryptoToken initFromPkcs11(String configFileDir, String defaultKey, String userPin) {
		CryptoToken result = null;

		Provider myPKCS11Prov = new sun.security.pkcs11.SunPKCS11(
				configFileDir);
		Security.insertProviderAt(myPKCS11Prov, 1);

		try {
			String signerAlias = null;
			PrivateKey signerPrivateKey = null;
			Provider privateKeyProvider = null;
			X509Certificate signerCert = null;
			X509Certificate issuerCert = null;
			Certificate[] chain = null;

			KeyStore ks = KeyStore.getInstance(PKCS11);
			ks.load(null, userPin.toCharArray());
			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				LOG.info(alias);
				
				if (defaultKey.equals(alias)) {
					signerAlias = defaultKey;
				}
			}

			if (signerAlias != null) {
				Certificate cert = ks.getCertificate(signerAlias);
				if (cert instanceof X509Certificate) {
					signerCert = (X509Certificate) cert;
				}

				chain = ks.getCertificateChain(signerAlias);
				
				issuerCert = getIssuerCertFromChain(signerCert, chain);
				Key key = ks.getKey(signerAlias, userPin.toCharArray());
				if(key instanceof PrivateKey){
					signerPrivateKey = (PrivateKey) key;
				}
				
				privateKeyProvider = ks.getProvider();

				result = new CryptoToken(signerPrivateKey, signerCert,
						issuerCert, chain, privateKeyProvider);
			} else {
				LOG.error("Default key \"" + defaultKey + "\" not found");
			}
		} catch (KeyStoreException e) {
			LOG.error("KeyStoreException" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			LOG.error("KeyStoreException" + e.getMessage());
		} catch (CertificateException e) {
			LOG.error("KeyStoreException" + e.getMessage());
		} catch (IOException e) {
			LOG.error("KeyStoreException" + e.getMessage());
		} catch (UnrecoverableKeyException e) {
			LOG.error("UnrecoverableKeyException" + e.getMessage());
		}
		
		return result;
	}

	/**
	 * So sanh issuerDN tu signer certificate voi subjectDN tu cert trong
	 * certchain de tim issuer certificate
	 * 
	 * @param signer
	 *            issuerDN from Signer's certificate
	 * @param issuer
	 *            subjectDN from Issuer's certificate
	 * @return boolean value, true if match
	 */
	private static boolean compareLdapName(String signer, String issuer) {
		boolean equal = true;
		try {
			LdapName signerDN = new LdapName(signer);
			LdapName issuerDN = new LdapName(issuer);
			List<Rdn> rdns = signerDN.getRdns();
			List<Rdn> twoRdns = issuerDN.getRdns();

			if (rdns.size() != twoRdns.size()) {
				equal = false;
			} else {
				for (Rdn rdn : twoRdns) {
					if (!rdns.contains(rdn)) {
						equal = false;
						break;
					}

				}
			}
		} catch (InvalidNameException e) {
			LOG.error("InvalidNameException: " + e.getMessage());
			equal = false;
		}

		return equal;
	}

	/**
	 * Get issuer's ceertificate from certchain
	 * 
	 * @param signerCert
	 *            Signer's certificate
	 * @param chain
	 *            Certchain from keystore
	 * @return X509Certificate object or may be null
	 */
	private static X509Certificate getIssuerCertFromChain(
			X509Certificate signerCert, Certificate[] chain) {
		X509Certificate issuerCert = null;
		if (chain != null && chain.length > 1) {
			for (Certificate c : chain) {
				if (c instanceof X509Certificate) {
					X509Certificate issuer = (X509Certificate) c;
					String issuerDN = issuer.getSubjectDN().toString();
					String subjectDN = signerCert.getIssuerDN().toString();
					LOG.info(issuerDN + " - " + subjectDN);
					if (compareLdapName(issuerDN, subjectDN)) {
						issuerCert = issuer;
						break;
					}
				}
			}
		}

		return issuerCert;
	}
}
