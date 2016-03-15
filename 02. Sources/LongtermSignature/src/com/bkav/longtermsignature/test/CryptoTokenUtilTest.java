package com.bkav.longtermsignature.test;

import org.apache.log4j.Logger;

import com.bkav.longtermsignature.cryptotoken.CryptoToken;
import com.bkav.longtermsignature.cryptotoken.CryptoTokenUtil;

public class CryptoTokenUtilTest {
	private static final Logger LOG = Logger
			.getLogger(CryptoTokenUtilTest.class);

	public static void main(String[] args) {
		pkcs11Test();
	}

	public static void pkcs11Test() {
		String configFileDir = "S:/WORK/2016/03-2016/BkavCA_Token_Config/"
				+ "Bkav_Token_Config.cfg";

		String defaultKey = "CÃ´ng ty TNHH Nguyá»n Minh Háº£i";
		String userPin = "12345678";
		
		CryptoTokenUtil tokenUtil = new CryptoTokenUtil();
		CryptoToken token = tokenUtil.initFromPkcs11(configFileDir, defaultKey, userPin);
		if(token == null){
			return;
		}
		 LOG.info("Signer's certificate: " + token.getSignerCert());
		 LOG.info("Issuer's certificate: " + token.getIssuerCert());
		// LOG.info("Signer's private key: " + token.getPrivateKey());
		// LOG.info("Issuer's certchain: " + token.getCertChain());
		LOG.info("Issuer's provider: " + token.getPrivateKeyProvider());
	}

	public static void pkcs12Test() {
		String path = "S:/KEYSTORE/KEY_2048/Server_TuanBS3.p12";
		String pass = "1";

		CryptoTokenUtil tokenUtil = new CryptoTokenUtil();
		CryptoToken token = tokenUtil.initFromPkcs12(path, pass);
		if(token == null){
			return;
		}
		// LOG.info("Signer's certificate: " + token.getSignerCert());
		// LOG.info("Issuer's certificate: " + token.getIssuerCert());
		// LOG.info("Signer's private key: " + token.getPrivateKey());
		// LOG.info("Issuer's certchain: " + token.getCertChain());
		LOG.info("Issuer's provider: " + token.getPrivateKeyProvider());
	}

	public static void cspTest() {
		String serial = "540373fc75801a7b136b8fafb2222a8e";
		CryptoTokenUtil tokenUtil = new CryptoTokenUtil();
		CryptoToken token = tokenUtil.initFromCSP(serial);
		if(token == null){
			return;
		}
		 LOG.info("Signer's certificate: " + token.getSignerCert());
		 LOG.info("Issuer's certificate: " + token.getIssuerCert());
		 LOG.info("Signer's private key: " + token.getPrivateKey());
		LOG.info("Issuer's certchain: " + token.getCertChain());
		// LOG.info("Issuer's provider: " + token.getPrivateKeyProvider());
	}
}
