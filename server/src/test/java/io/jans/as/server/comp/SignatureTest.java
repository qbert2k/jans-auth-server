/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.comp;

import static org.testng.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;

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

/**
 * @author Javier Rojas Blum Date: 12.03.2012
 */
//public class SignatureTest extends BaseTest {

public class SignatureTest {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

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
				"CN=Test CA Certificate");

		Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

		RSAPrivateKey privateKey = key.getPrivateKey();
		RSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = "Hello World!";
		RSASigner rsaSigner1 = new RSASigner(SignatureAlgorithm.RS256, privateKey);
		String signature = rsaSigner1.generateSignature(signingInput);
		RSASigner rsaSigner2 = new RSASigner(SignatureAlgorithm.RS256, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));
		RSASigner rsaSigner3 = new RSASigner(SignatureAlgorithm.RS256, certificate);
		assertTrue(rsaSigner3.validateSignature(signingInput, signature));
	}

	@Test
	public void generateRS384Keys() throws Exception {
		showTitle("TEST: generateRS384Keys");

		KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS384,
				"CN=Test CA Certificate");

		Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

		RSAPrivateKey privateKey = key.getPrivateKey();
		RSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = "Hello World!";
		RSASigner rsaSigner1 = new RSASigner(SignatureAlgorithm.RS384, privateKey);
		String signature = rsaSigner1.generateSignature(signingInput);
		RSASigner rsaSigner2 = new RSASigner(SignatureAlgorithm.RS384, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));
		RSASigner rsaSigner3 = new RSASigner(SignatureAlgorithm.RS384, certificate);
		assertTrue(rsaSigner3.validateSignature(signingInput, signature));
	}

	@Test
	public void generateRS512Keys() throws Exception {
		showTitle("TEST: generateRS512Keys");

		KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(SignatureAlgorithm.RS512,
				"CN=Test CA Certificate");

		Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

		RSAPrivateKey privateKey = key.getPrivateKey();
		RSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = "Hello World!";
		RSASigner rsaSigner1 = new RSASigner(SignatureAlgorithm.RS512, privateKey);
		String signature = rsaSigner1.generateSignature(signingInput);
		RSASigner rsaSigner2 = new RSASigner(SignatureAlgorithm.RS512, publicKey);
		assertTrue(rsaSigner2.validateSignature(signingInput, signature));
		RSASigner rsaSigner3 = new RSASigner(SignatureAlgorithm.RS512, certificate);
		assertTrue(rsaSigner3.validateSignature(signingInput, signature));
	}

	@Test
	public void generateES256Keys() throws Exception {
		showTitle("TEST: generateES256Keys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES256,
				"CN=Test CA Certificate");

		Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

		ECDSAPrivateKey privateKey = key.getPrivateKey();
		ECDSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = "Hello World!";
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES256, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES256, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES256, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));
	}

	@Test
	public void generateES256KKeys() throws Exception {
		showTitle("TEST: generateES256KKeys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES256K,
				"CN=Test CA Certificate");

		Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

		ECDSAPrivateKey privateKey = key.getPrivateKey();
		ECDSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = "Hello World!";
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES256K, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES256K, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES256K, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));
		
		int bitCount = privateKey.getD().bitCount();
		int bitLength = privateKey.getD().bitLength();
		
		bitLength = bitLength;
	}

	@Test
	public void generateES384Keys() throws Exception {
		showTitle("TEST: generateES384Keys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES384,
				"CN=Test CA Certificate");

		Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

		ECDSAPrivateKey privateKey = key.getPrivateKey();
		ECDSAPublicKey publicKey = key.getPublicKey();
		Certificate certificate = key.getCertificate();

		System.out.println(key);

		String signingInput = "Hello World!";
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES384, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES384, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES384, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));
	}

	@Test
	public void generateES512Keys() throws Exception {
		showTitle("TEST: generateES512Keys");

		KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(SignatureAlgorithm.ES512,
				"CN=Test CA Certificate");
		ECDSAPrivateKey privateKey = keyFactory.getPrivateKey();
		ECDSAPublicKey publicKey = keyFactory.getPublicKey();
		Certificate certificate = keyFactory.getCertificate();

		System.out.println("PRIVATE KEY");
		System.out.println(privateKey);
		System.out.println("PUBLIC KEY");
		System.out.println(publicKey);
		System.out.println("CERTIFICATE");
		System.out.println(certificate);

		String signingInput = "Hello World!";
		ECDSASigner ecdsaSigner1 = new ECDSASigner(SignatureAlgorithm.ES512, privateKey);
		String signature = ecdsaSigner1.generateSignature(signingInput);
		ECDSASigner ecdsaSigner2 = new ECDSASigner(SignatureAlgorithm.ES512, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
		ECDSASigner ecdsaSigner3 = new ECDSASigner(SignatureAlgorithm.ES512, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));
	}

	@Test
	public void generateED25519Keys() throws Exception {
		showTitle("TEST: generateED25519Keys");

		KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED25519,
				"CN=Test CA Certificate");
		EDDSAPrivateKey privateKey = keyFactory.getPrivateKey();
		EDDSAPublicKey publicKey = keyFactory.getPublicKey();
		Certificate certificate = keyFactory.getCertificate();

		System.out.println("PRIVATE KEY");
		System.out.println(privateKey);
		System.out.println("PUBLIC KEY");
		System.out.println(publicKey);
		System.out.println("CERTIFICATE");
		System.out.println(certificate);

		String signingInput = "Hello World!";
		EDDSASigner eddsaSigner1 = new EDDSASigner(SignatureAlgorithm.ED25519, privateKey);
		String signature = eddsaSigner1.generateSignature(signingInput);

		EDDSASigner ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.ED25519, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		EDDSASigner ecdsaSigner3 = new EDDSASigner(SignatureAlgorithm.ED25519, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		int privateKeyLen = getDecodedKeysLength(privateKey);
		int publicKeyLen = getDecodedKeysLength(publicKey);

		assertTrue(Ed25519.SECRET_KEY_SIZE == privateKeyLen);
		assertTrue(Ed25519.PUBLIC_KEY_SIZE == publicKeyLen);
	}

	@Test
	public void generateED448Keys() throws Exception {
		showTitle("TEST: generateED448Keys");

		KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.ED448,
				"CN=Test CA Certificate");
		EDDSAPrivateKey privateKey = keyFactory.getPrivateKey();
		EDDSAPublicKey publicKey = keyFactory.getPublicKey();
		Certificate certificate = keyFactory.getCertificate();

		System.out.println("PRIVATE KEY");
		System.out.println(privateKey);
		System.out.println("PUBLIC KEY");
		System.out.println(publicKey);
		System.out.println("CERTIFICATE");
		System.out.println(certificate);

		String signingInput = "Hello World!";
		EDDSASigner eddsaSigner1 = new EDDSASigner(SignatureAlgorithm.ED448, privateKey);
		String signature = eddsaSigner1.generateSignature(signingInput);

		EDDSASigner ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.ED448, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		EDDSASigner ecdsaSigner3 = new EDDSASigner(SignatureAlgorithm.ED448, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		int privateKeyLen = getDecodedKeysLength(privateKey);
		int publicKeyLen = getDecodedKeysLength(publicKey);

		assertTrue(Ed448.SECRET_KEY_SIZE == privateKeyLen);
		assertTrue(Ed448.PUBLIC_KEY_SIZE == publicKeyLen);
	}

	@Test
	public void generateEDDSAKeys() throws Exception {
		showTitle("TEST: generateEDDSAKeys");

		KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> keyFactory = new EDDSAKeyFactory(SignatureAlgorithm.EDDSA,
				"CN=Test CA Certificate");
		EDDSAPrivateKey privateKey = keyFactory.getPrivateKey();
		EDDSAPublicKey publicKey = keyFactory.getPublicKey();
		Certificate certificate = keyFactory.getCertificate();

		System.out.println("PRIVATE KEY");
		System.out.println(privateKey);
		System.out.println("PUBLIC KEY");
		System.out.println(publicKey);
		System.out.println("CERTIFICATE");
		System.out.println(certificate);

		String signingInput = "Hello World!";
		EDDSASigner eddsaSigner1 = new EDDSASigner(SignatureAlgorithm.EDDSA, privateKey);
		String signature = eddsaSigner1.generateSignature(signingInput);

		EDDSASigner ecdsaSigner2 = new EDDSASigner(SignatureAlgorithm.EDDSA, publicKey);
		assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

		EDDSASigner ecdsaSigner3 = new EDDSASigner(SignatureAlgorithm.EDDSA, certificate);
		assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

		int privateKeyLen = getDecodedKeysLength(privateKey);
		int publicKeyLen = getDecodedKeysLength(publicKey);

		assertTrue(Ed25519.SECRET_KEY_SIZE == privateKeyLen);
		assertTrue(Ed25519.PUBLIC_KEY_SIZE == publicKeyLen);
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
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(eddsaPrivateKey.getPrivateKeyData());
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
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(eddsaPublicKey.getPublicKeyData());
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
