package com.bkav.longtermsignature.test;

import java.security.cert.X509CRL;

import com.bkav.longtermsignature.cryptotoken.CryptoToken;
import com.bkav.longtermsignature.cryptotoken.CryptoTokenUtil;
import com.bkav.longtermsignature.validationservice.CRLValidator;

public class TestCRLValidator {
	public static void main(String[] args) {
		String configFileDir = "S:/WORK/2016/03-2016/BkavCA_Token_Config/"
				+ "Bkav_Token_Config.cfg";

		String defaultKey = "CÃ´ng ty TNHH Nguyá»n Minh Háº£i";
		String userPin = "12345678";

		CryptoTokenUtil tokenUtil = new CryptoTokenUtil();
		CryptoToken token = tokenUtil.initFromPkcs11(configFileDir, defaultKey,
				userPin);
		X509CRL crl = CRLValidator.getCRLDistribution(token.getSignerCert(),
				token.getIssuerCert(), false);
		
		System.out.println(crl);
	}
}
