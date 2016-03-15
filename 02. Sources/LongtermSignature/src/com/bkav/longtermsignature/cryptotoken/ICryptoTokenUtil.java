package com.bkav.longtermsignature.cryptotoken;

public interface ICryptoTokenUtil {
	/**
	 * Khoi tao doi tuong CryptoToken tu file p12
	 * 
	 * @param keystorePath
	 *            Keystore's directory
	 * @param keystorePass
	 *            Keystore's password
	 * @return a CryptoToken object or may be null
	 */
	public CryptoToken initFromPkcs12(String keystorePath, String keystorePass);

	/**
	 * Khoi tao doi tuong CryptoToken tu PKCS11
	 * 
	 * @param defaultKey
	 *            Signer's certificate alias
	 * @param userPin
	 *            token's pin
	 * @return a CryptoToken object or may be null
	 */
	public CryptoToken initFromPkcs11(String configFileDir, String defaultKey, String userPin);

	/**
	 * Khoi tao doi tuong CryptoToken tu Window-MY
	 * 
	 * @param serialNumber
	 *            Signer's serial number
	 * @return a CryptoToken object or may be null
	 */
	public CryptoToken initFromCSP(String serialNumber);
}
