package com.bkav.longtermsignature.test;

import java.io.IOException;
import java.util.Collections;

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
import org.apache.poi.poifs.crypt.dsig.services.SignaturePolicyService;

import com.bkav.longtermsignature.cryptotoken.CryptoToken;
import com.bkav.longtermsignature.cryptotoken.CryptoTokenUtil;

public class OOXMLtest {
	public static void main(String[] args) {
		String input = "S:/WORK/2016/03-2016/Test Files/input.docx";
		String path = "S:/WORK/Keystores/KEY_2048/Server_TuanBS3.p12";
		String pass = "1";

		CryptoTokenUtil tokenUtil = new CryptoTokenUtil();
		CryptoToken token = tokenUtil.initFromPkcs12(path, pass);

		EnvelopedSignatureFacet envelopedSignatureFacet = new EnvelopedSignatureFacet();
		KeyInfoSignatureFacet keyInfoSignatureFacet = new KeyInfoSignatureFacet();
		XAdESSignatureFacet xadesSignatureFacet = new XAdESSignatureFacet();
		XAdESXLSignatureFacet xadesXLSignatureFacet = new XAdESXLSignatureFacet();
	}
}
