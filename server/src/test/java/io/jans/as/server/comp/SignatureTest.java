/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.comp;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;

import org.testng.annotations.Test;

import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.Key;
import io.jans.as.model.crypto.KeyFactory;
import io.jans.as.model.crypto.signature.ECDSAKeyFactory;
import io.jans.as.model.crypto.signature.ECDSAPrivateKey;
import io.jans.as.model.crypto.signature.ECDSAPublicKey;
import io.jans.as.model.crypto.signature.EDDSAKeyFactory;
import io.jans.as.model.crypto.signature.EDDSAPrivateKey;
import io.jans.as.model.crypto.signature.EDDSAPublicKey;
import io.jans.as.model.crypto.signature.RSAKeyFactory;
import io.jans.as.model.crypto.signature.RSAPrivateKey;
import io.jans.as.model.crypto.signature.RSAPublicKey;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jws.ECDSASigner;
import io.jans.as.model.jws.EDDSASigner;
import io.jans.as.model.jws.RSASigner;
import io.jans.as.model.util.Base64Util;

/**
 * @author Javier Rojas Blum Date: 12.03.2012
 */
//public class SignatureTest extends BaseTest {

public class SignatureTest {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static String DEF_CERTIFICATE_OWN = "CN=Test CA Certificate";
	private static String DEF_INPUT = "Hello World!";

	public static void showTitle(String title) {
		title = "TEST: " + title;

		System.out.println("#######################################################");
		System.out.println(title);
		System.out.println("#######################################################");
	}

	@Test
	public void generateRS256Keys() throws Exception {
		showTitle("TEST: generateRS256Keys");

		KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS256,
				DEF_CERTIFICATE_OWN);

		Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

		RSAPrivateKey privateKey = key.getPrivateKey();
		RSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = DEF_INPUT;
		RSASigner rsaSigner1 = new RSASigner(SignatureAlgorithm.RS256, privateKey);
		String signature = rsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		
		RSASigner rsaSigner2 = new RSASigner(SignatureAlgorithm.RS256, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));
		RSASigner rsaSigner3 = new RSASigner(SignatureAlgorithm.RS256, certificate);
		assertTrue(rsaSigner3.validateSignature(signingInput, signature));

		keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS256, DEF_CERTIFICATE_OWN);

		Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
		RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
		Certificate certificateWrong = keyWrong.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		rsaSigner2 = new RSASigner(SignatureAlgorithm.RS256, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));

		assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		RSASigner rsaSigner4 = new RSASigner(SignatureAlgorithm.RS256, publicKeyWrong);
		assertFalse(rsaSigner4.validateSignature(signingInput, signature));

		assertFalse(rsaSigner4.validateSignature(signingInput, signature));
		assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		RSASigner rsaSigner5 = new RSASigner(SignatureAlgorithm.RS256, certificateWrong);
		assertFalse(rsaSigner5.validateSignature(signingInput, signature));
		assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	@Test
	public void generateRS384Keys() throws Exception {
		showTitle("TEST: generateRS384Keys");

		KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS384,
				DEF_CERTIFICATE_OWN);

		Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

		RSAPrivateKey privateKey = key.getPrivateKey();
		RSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = DEF_INPUT;
		RSASigner rsaSigner1 = new RSASigner(SignatureAlgorithm.RS384, privateKey);
		String signature = rsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		
		RSASigner rsaSigner2 = new RSASigner(SignatureAlgorithm.RS384, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));
		RSASigner rsaSigner3 = new RSASigner(SignatureAlgorithm.RS384, certificate);
		assertTrue(rsaSigner3.validateSignature(signingInput, signature));

		keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS384, DEF_CERTIFICATE_OWN);

		Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
		RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
		Certificate certificateWrong = keyWrong.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		rsaSigner2 = new RSASigner(SignatureAlgorithm.RS384, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));

		assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		RSASigner rsaSigner4 = new RSASigner(SignatureAlgorithm.RS384, publicKeyWrong);
		assertFalse(rsaSigner4.validateSignature(signingInput, signature));

		assertFalse(rsaSigner4.validateSignature(signingInput, signature));
		assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		RSASigner rsaSigner5 = new RSASigner(SignatureAlgorithm.RS384, certificateWrong);
		assertFalse(rsaSigner5.validateSignature(signingInput, signature));
		assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	@Test
	public void generateRS512Keys() throws Exception {
		showTitle("TEST: generateRS512Keys");

		KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS512,
				DEF_CERTIFICATE_OWN);

		Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

		RSAPrivateKey privateKey = key.getPrivateKey();
		RSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = DEF_INPUT;
		RSASigner rsaSigner1 = new RSASigner(SignatureAlgorithm.RS512, privateKey);
		String signature = rsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		
		RSASigner rsaSigner2 = new RSASigner(SignatureAlgorithm.RS512, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));
		RSASigner rsaSigner3 = new RSASigner(SignatureAlgorithm.RS512, certificate);
		assertTrue(rsaSigner3.validateSignature(signingInput, signature));
		
		keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS512, DEF_CERTIFICATE_OWN);

		Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
		RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
		Certificate certificateWrong = keyWrong.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		rsaSigner2 = new RSASigner(SignatureAlgorithm.RS512, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));

		assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		RSASigner rsaSigner4 = new RSASigner(SignatureAlgorithm.RS512, publicKeyWrong);
		assertFalse(rsaSigner4.validateSignature(signingInput, signature));

		assertFalse(rsaSigner4.validateSignature(signingInput, signature));
		assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		RSASigner rsaSigner5 = new RSASigner(SignatureAlgorithm.RS512, certificateWrong);
		assertFalse(rsaSigner5.validateSignature(signingInput, signature));
		assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));		
	}

	@Test
	public void generateES256Keys() throws Exception {
		showTitle("TEST: generateES256Keys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES256,
				DEF_CERTIFICATE_OWN);

		Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

		ECDSAPrivateKey privateKey = key.getPrivateKey();
		ECDSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = DEF_INPUT;
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES256, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES256, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES256, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
				.getParameterSpec(SignatureAlgorithm.ES256.getCurve().getAlias());
		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey.getD(), ecSpec);

		ECPoint pointQ = ecSpec.getCurve().createPoint(publicKey.getX(), publicKey.getY());
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

		java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
		BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
		BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

		ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
		ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

		assertTrue(SignatureAlgorithm.ES256.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
		assertTrue(SignatureAlgorithm.ES256.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

		assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP256R1Curve.class);
		assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP256R1Curve.class);

		assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP256R1Curve().getFieldSize());
		assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP256R1Curve().getFieldSize());

		keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES256, DEF_CERTIFICATE_OWN);

		Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

		ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
		Certificate certificateWrong = keyWrong.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES256, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner4 = new ECDSASigner(SignatureAlgorithm.ES256, publicKeyWrong);
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner5 = new ECDSASigner(SignatureAlgorithm.ES256, certificateWrong);
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	@Test
	public void generateES256KKeys() throws Exception {
		showTitle("TEST: generateES256KKeys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES256K,
				DEF_CERTIFICATE_OWN);

		Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

		ECDSAPrivateKey privateKey = key.getPrivateKey();
		ECDSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = DEF_INPUT;
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES256K, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES256K, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES256K, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
				.getParameterSpec(SignatureAlgorithm.ES256K.getCurve().getAlias());
		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey.getD(), ecSpec);

		ECPoint pointQ = ecSpec.getCurve().createPoint(publicKey.getX(), publicKey.getY());
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

		java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
		BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
		BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

		ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
		ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

		assertTrue(SignatureAlgorithm.ES256K.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
		assertTrue(SignatureAlgorithm.ES256K.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

		assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP256K1Curve.class);
		assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP256K1Curve.class);

		assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP256K1Curve().getFieldSize());
		assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP256K1Curve().getFieldSize());

		keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES256K, DEF_CERTIFICATE_OWN);

		Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

		ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
		Certificate certificateWrong = keyWrong.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES256K, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner4 = new ECDSASigner(SignatureAlgorithm.ES256K, publicKeyWrong);
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner5 = new ECDSASigner(SignatureAlgorithm.ES256K, certificateWrong);
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	@Test
	public void generateES384Keys() throws Exception {
		showTitle("TEST: generateES384Keys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES384,
				DEF_CERTIFICATE_OWN);

		Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

		ECDSAPrivateKey privateKey = key.getPrivateKey();
		ECDSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = DEF_INPUT;
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES384, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES384, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES384, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
				.getParameterSpec(SignatureAlgorithm.ES384.getCurve().getAlias());
		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey.getD(), ecSpec);

		ECPoint pointQ = ecSpec.getCurve().createPoint(publicKey.getX(), publicKey.getY());
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

		java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
		BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
		BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

		ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
		ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

		assertTrue(SignatureAlgorithm.ES384.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
		assertTrue(SignatureAlgorithm.ES384.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

		assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP384R1Curve.class);
		assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP384R1Curve.class);

		assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP384R1Curve().getFieldSize());
		assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP384R1Curve().getFieldSize());

		keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES384, DEF_CERTIFICATE_OWN);

		Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

		ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
		Certificate certificateWrong = keyWrong.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES384, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner4 = new ECDSASigner(SignatureAlgorithm.ES384, publicKeyWrong);
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner5 = new ECDSASigner(SignatureAlgorithm.ES384, certificateWrong);
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	@Test
	public void generateES512Keys() throws Exception {
		showTitle("TEST: generateES512Keys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES512,
				DEF_CERTIFICATE_OWN);
		ECDSAPrivateKey privateKey = keyFactory.getPrivateKey();
		ECDSAPublicKey publicKey = keyFactory.getPublicKey();
		Certificate certificate = keyFactory.getCertificate();

		System.out.println("PRIVATE KEY");
		System.out.println(privateKey);
		System.out.println("PUBLIC KEY");
		System.out.println(publicKey);
		System.out.println("CERTIFICATE");
		System.out.println(certificate);

		String signingInput = DEF_INPUT;
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES512, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES512, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES512, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
				.getParameterSpec(SignatureAlgorithm.ES512.getCurve().getAlias());
		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey.getD(), ecSpec);

		ECPoint pointQ = ecSpec.getCurve().createPoint(publicKey.getX(), publicKey.getY());
		ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

		java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
		BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
		BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

		ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
		ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

		assertTrue(SignatureAlgorithm.ES512.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
		assertTrue(SignatureAlgorithm.ES512.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

		assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP521R1Curve.class);
		assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP521R1Curve.class);

		assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP521R1Curve().getFieldSize());
		assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP521R1Curve().getFieldSize());

		keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES512, DEF_CERTIFICATE_OWN);

		Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

		ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
		Certificate certificateWrong = keyWrong.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES512, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner4 = new ECDSASigner(SignatureAlgorithm.ES512, publicKeyWrong);
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		ECDSASigner ecdsaSigner5 = new ECDSASigner(SignatureAlgorithm.ES512, certificateWrong);
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	@Test
	public void generateED25519Keys() throws Exception {
		showTitle("TEST: generateED25519Keys");

		KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED25519,
				DEF_CERTIFICATE_OWN);
		EDDSAPrivateKey privateKey = keyFactory.getPrivateKey();
		EDDSAPublicKey publicKey = keyFactory.getPublicKey();
		Certificate certificate = keyFactory.getCertificate();

		System.out.println("PRIVATE KEY");
		System.out.println(privateKey);
		System.out.println("PUBLIC KEY");
		System.out.println(publicKey);
		System.out.println("CERTIFICATE");
		System.out.println(certificate);

		String signingInput = DEF_INPUT;
		EDDSASigner eddsaSigner1 = new EDDSASigner(SignatureAlgorithm.ED25519, privateKey);
		String signature = eddsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		

		EDDSASigner ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.ED25519, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.ED25519, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		EDDSASigner ecdsaSigner3 = new EDDSASigner(SignatureAlgorithm.ED25519, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		int privateKeyLen = getDecodedKeysLength(privateKey);
		int publicKeyLen = getDecodedKeysLength(publicKey);

		assertTrue(Ed25519.SECRET_KEY_SIZE == privateKeyLen);
		assertTrue(Ed25519.PUBLIC_KEY_SIZE == publicKeyLen);

		keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED25519, DEF_CERTIFICATE_OWN);
		EDDSAPublicKey publicKeyWrong = keyFactory.getPublicKey();
		Certificate certificateWrong = keyFactory.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.ED25519, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		EDDSASigner ecdsaSigner4 = new EDDSASigner(SignatureAlgorithm.ED25519, publicKeyWrong);
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		EDDSASigner ecdsaSigner5 = new EDDSASigner(SignatureAlgorithm.ED25519, certificateWrong);
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	@Test
	public void generateED448Keys() throws Exception {
		showTitle("TEST: generateED448Keys");

		KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED448,
				DEF_CERTIFICATE_OWN);
		EDDSAPrivateKey privateKey = keyFactory.getPrivateKey();
		EDDSAPublicKey publicKey = keyFactory.getPublicKey();
		Certificate certificate = keyFactory.getCertificate();

		System.out.println("PRIVATE KEY");
		System.out.println(privateKey);
		System.out.println("PUBLIC KEY");
		System.out.println(publicKey);
		System.out.println("CERTIFICATE");
		System.out.println(certificate);

		String signingInput = DEF_INPUT;
		EDDSASigner eddsaSigner1 = new EDDSASigner(SignatureAlgorithm.ED448, privateKey);
		String signature = eddsaSigner1.generateSignature(signingInput);
		assertTrue(signature.length() > 0);		

		EDDSASigner ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.ED448, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		EDDSASigner ecdsaSigner3 = new EDDSASigner(SignatureAlgorithm.ED448, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		int privateKeyLen = getDecodedKeysLength(privateKey);
		int publicKeyLen = getDecodedKeysLength(publicKey);

		assertTrue(Ed448.SECRET_KEY_SIZE == privateKeyLen);
		assertTrue(Ed448.PUBLIC_KEY_SIZE == publicKeyLen);

		keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED448, DEF_CERTIFICATE_OWN);
		EDDSAPublicKey publicKeyWrong = keyFactory.getPublicKey();
		Certificate certificateWrong = keyFactory.getCertificate();

		byte[] signatureArray = Base64Util.base64urldecode(signature);
		signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
		String signatureWrong = Base64Util.base64urlencode(signatureArray);

		String signingInputWrong = signingInput + 'z';

		ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.ED448, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

		EDDSASigner ecdsaSigner4 = new EDDSASigner(SignatureAlgorithm.ED448, publicKeyWrong);
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

		assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

		EDDSASigner ecdsaSigner5 = new EDDSASigner(SignatureAlgorithm.ED448, certificateWrong);
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
		assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
		assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
	}

	/**
	 * 
	 * @param eddsaPrivateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private int getDecodedKeysLength(EDDSAPrivateKey eddsaPrivateKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		int resLength = 0;
		PKCS8EncodedKeySpec privateKeySpec = eddsaPrivateKey.getPrivateKeySpec();
		java.security.KeyFactory keyFactory = java.security.KeyFactory
				.getInstance(eddsaPrivateKey.getSignatureAlgorithm().getName());
		BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		String privateKeyStr = privateKey.toString();
		String privateKeyValueStr;
		while (true) {
			if (!privateKeyStr.contains(eddsaPrivateKey.getSignatureAlgorithm().getAlgorithm()))
				break;
			if (!privateKeyStr.contains("Private Key"))
				break;
			int lastIdx = privateKeyStr.lastIndexOf("public data:");
			privateKeyValueStr = privateKeyStr.substring(lastIdx + new String("public data:").length());
			resLength = privateKeyValueStr.trim().length() / 2;
			break;
		}
		return resLength;
	}

	/**
	 * 
	 * @param eddsaPublicKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private int getDecodedKeysLength(EDDSAPublicKey eddsaPublicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		int resLength = 0;
		X509EncodedKeySpec publicKeySpec = eddsaPublicKey.getPublicKeySpec();
		java.security.KeyFactory keyFactory = java.security.KeyFactory
				.getInstance(eddsaPublicKey.getSignatureAlgorithm().getName());
		BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		String publicKeyStr = publicKey.toString();
		String publicKeyValueStr;
		while (true) {
			if (!publicKeyStr.contains(eddsaPublicKey.getSignatureAlgorithm().getAlgorithm()))
				break;
			if (!publicKeyStr.contains("Public Key"))
				break;
			int lastIdx = publicKeyStr.lastIndexOf("public data:");
			publicKeyValueStr = publicKeyStr.substring(lastIdx + new String("public data:").length());
			resLength = publicKeyValueStr.trim().length() / 2;
			break;
		}
		return resLength;
	}
}
