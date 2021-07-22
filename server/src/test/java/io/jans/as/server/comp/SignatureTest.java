/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.comp;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
//import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;
import org.testng.annotations.Test;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

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
import io.jans.as.model.jws.RSASigner;
//import io.jans.as.server.BaseTest;
import io.jans.as.model.util.Util;

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
	
/*	
	private static EdECPoint byteArrayToEdPoint(byte[] arr)
	{
	    byte msb = arr[arr.length - 1];
	    boolean xOdd = (msb & 0x80) != 0;
	    arr[arr.length - 1] &= (byte) 0x7F;
	    reverse(arr);
	    BigInteger y = new BigInteger(1, arr);
	    return new EdECPoint(xOdd, y);
	}	
*/	

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
		
//      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(signatureAlgorithm.getCurve().getName());
//		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("" SignatureAlgorithm. signatureAlgorithm.getCurve().getAlias());

/*		
		KeyPairGenerator keyGen_1 = KeyPairGenerator.getInstance("EDDSA", "BC");
		KeyPairGenerator keyGen_2 = KeyPairGenerator.getInstance("Ed25519", "BC");
		KeyPairGenerator keyGen_3 = KeyPairGenerator.getInstance("Ed448", "BC");		
		KeyPairGenerator keyGen_4 = KeyPairGenerator.getInstance("ECDSA", "BC");
*/
/*		
		Ed25519Sign.KeyPair kp = Ed25519Sign.KeyPair.newKeyPair();
		
		Ed25519Sign.KeyPair tk = Ed25519Sign.KeyPair.newKeyPair();
		OctetKeyPair k1 = new OctetKeyPair.Builder(Curve.X25519, Base64URL.encode(tk.getPublicKey())).
			d(Base64URL.encode(tk.getPrivateKey())).
			build();
		OctetKeyPair k2 = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(tk.getPublicKey())).
			d(Base64URL.encode(tk.getPrivateKey())).
			build();		
		
		OctetKeyPair keyPair = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(kp.getPublicKey())).
				d(Base64URL.encode(kp.getPrivateKey())).
				build(); 
*/
/*
		return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(kp.getPublicKey())).
			d(Base64URL.encode(kp.getPrivateKey())).
			build();
*/
	
/*		

		{
			String signingInput = "Hello World!";
			
		    KeyPair keyPair;
		    
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
	        
	        keyGen.initialize(new EdDSAParameterSpec("Ed25519"), new SecureRandom());

	        keyPair = keyGen.generateKeyPair();
	        
	        BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey) keyPair.getPrivate();
	        BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyPair.getPublic();
	        
	        byte [] privateKeyData = privateKey.getEncoded();
	        byte [] publicKeyData = publicKey.getEncoded();
	        
//	        Ed25519PublicKeyParameters params = new Ed25519PublicKeyParameters(publicKeyData, 0);
	        
//	        EdECPoint 
	        
	        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("Ed25519");
//	        org.bouncycastle.jcajce.spec.RawEncodedKeySpec pkcs8EncodedKeySpec = new org.bouncycastle.jcajce.spec.RawEncodedKeySpec(publicKeySpecData);
	        
	        PKCS8EncodedKeySpec pkcs8EncodedKeySpec_private = new PKCS8EncodedKeySpec(privateKeyData);
	        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyData);	        
	        
//	        EdECPublicKeySpec
	        
	        BCEdDSAPrivateKey privateKey_private = (BCEdDSAPrivateKey)keyFactory.generatePrivate(pkcs8EncodedKeySpec_private);
	        BCEdDSAPublicKey publicKey_1 = (BCEdDSAPublicKey)keyFactory.generatePublic(publicKeySpec);	        
	        
	        //BCEdDSAPublicKey publicKeySpec_1 = (BCEdDSAPublicKey)keyFactory.generatePublic(pkcs8EncodedKeySpec);
	        
	        //BCEdDSAPublicKey publicKeySpec_1 = (BCEdDSAPublicKey)keyFactory.generatePublic(pkcs8EncodedKeySpec);

	        byte [] privateKeyData_private = privateKey_private.getEncoded();
	        byte [] publicKeyData_1 = publicKey_1.getEncoded();	        
	        
            assertTrue(Arrays.compare(privateKeyData, privateKeyData_private) == 0);	        
            assertTrue(Arrays.compare(publicKeyData, publicKeyData_1) == 0);            
	        
	        
//	        byte [] publicKeySpecData_1 = publicKeySpec_1.getEncoded();
	        
//            assertTrue(Arrays.compare(publicKeySpecData, publicKeySpecData_1) == 0);	        
	        
	        
//	        BCEdDSAPublicKey publicKeySpec_1 = new BCEdDSAPublicKey(params);	        
	        
	        
//	        org.bouncycastle.crypto.params.Ed25519PublicKeyParameters params; 
	        
//	        public Ed25519PublicKeyParameters(byte[] buf)
	        
	        
//	        byte [] publicKeySpecData = publicKeySpec.getPointEncoding();	        
	        
//	        org.bouncycastle.jcajce.provider.asymmetric.edec
//	        org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
//	        org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
	        
//	        keyPair  = keyPair;
	        
            Signature signer = Signature.getInstance("Ed25519", "BC");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes());
            
            byte [] signature = signer.sign();
            Base64URL signatureBase64 = Base64URL.encode(signature);

            Signature virify = Signature.getInstance("Ed25519", "BC");
            virify.initVerify(publicKey);
            
            virify.update(signingInput.getBytes());
            
            assertTrue(virify.verify(signatureBase64.decode()));            
		}
		
		{
			String signingInput = "Hello World!";
			
			Ed25519Sign.KeyPair tk = Ed25519Sign.KeyPair.newKeyPair();
	        
			byte [] privateKeyData = tk.getPrivateKey();
			byte [] publicKeyData = tk.getPublicKey();			
			
			OctetKeyPair k = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(tk.getPublicKey())).
					d(Base64URL.encode(tk.getPrivateKey())).
					build();
			Ed25519Signer signer = new Ed25519Signer(k);
			Ed25519Verifier verifier = new Ed25519Verifier(k.toPublicJWK());
				
			JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.EdDSA).build();				
			
			Base64URL s = signer.sign(h, signingInput.getBytes());
			assertTrue(verifier.verify(h, signingInput.getBytes(), s));
		}
*/		
//		keyGen_4 = keyGen_4;
		{
/*			
			String signingInput = "Hello World!";
			
			KeyPair keyPair;
			    
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
		        
	        keyGen.initialize(new EdDSAParameterSpec("Ed25519"), new SecureRandom());

	        keyPair = keyGen.generateKeyPair();
		        
	        BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey) keyPair.getPrivate();
	        BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyPair.getPublic();
	        
	        byte [] privateKeyArray = privateKey.getEncoded();
	        byte [] publicKeyArray = publicKey.getEncoded();
	        
			OctetKeyPair octKeyPair = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(publicKey.getEncoded())).
					d(Base64URL.encode(privateKey.getEncoded())).build();
			
			com.nimbusds.jose.crypto.Ed25519Signer signer = new com.nimbusds.jose.crypto.Ed25519Signer(octKeyPair);
			
			Base64URL base64Sign = signer.sign(new JWSHeader.Builder(JWSAlgorithm.EdDSA).build(), signingInput.getBytes());
			
			OctetKeyPair octKeyPairPublic = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(keyPair.getPublic().getEncoded())).build();		
			
			com.nimbusds.jose.crypto.Ed25519Verifier verifiyer = new com.nimbusds.jose.crypto.Ed25519Verifier(octKeyPairPublic);
			
			boolean verifyRes = verifiyer.verify(new JWSHeader.Builder(JWSAlgorithm.EdDSA).build(), signingInput.getBytes(), base64Sign);
			
            assertTrue(verifyRes);
*/            
            
/*            
            
    		Ed25519Sign.KeyPair tk = Ed25519Sign.KeyPair.newKeyPair();
    		OctetKeyPair k = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(tk.getPublicKey())).
    			d(Base64URL.encode(tk.getPrivateKey())).
    			build();
    		Ed25519Signer signer = new Ed25519Signer(k);
    		Ed25519Verifier verifier = new Ed25519Verifier(k.toPublicJWK());

    		JWSHeader h1 = new JWSHeader.Builder(JWSAlgorithm.HS256).
    			build();

    		try {
    			signer.sign(h1, new byte[] {1,2,3});
    			fail("should fail with alg HS256");

    		} catch (JOSEException e) {
    			// Passed
    		}

    		try {
    			// Signature is invalid, but should throw instead of returning false
    			verifier.verify(h1, new byte[] {1,2,3}, Base64URL.encode(new byte[64]));
    			fail("should fail with alg HS256");

    		} catch (JOSEException e) {
    			// Passed
    		}
*/            
            
/*            
			String signingInput = "Hello World!";
			
			Ed25519Sign.KeyPair tk = Ed25519Sign.KeyPair.newKeyPair();
			
			OctetKeyPair k = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(tk.getPublicKey())).
					d(Base64URL.encode(tk.getPrivateKey())).
					build();
			Ed25519Signer signer = new Ed25519Signer(k);
			Ed25519Verifier verifier = new Ed25519Verifier(k.toPublicJWK());
				
			JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.EdDSA).build();				
			
			Base64URL s = signer.sign(h, signingInput.getBytes());
			assertTrue(verifier.verify(h, signingInput.getBytes(), s));            
*/			
/*			
	        final List<String> aliases = cryptoProvider.getKeys();
	        for (String keyId : aliases) {
	            if (keyId.endsWith(use.getParamName()  + "_" + algorithm.getName().toLowerCase())) {
	                return keyId;
	            }
	        }
*/	        		
			
//			Base
			
//            assertTrue(Arrays.compare(publicKeyData, publicKeyData_1) == 0);			
			
		}
	
/*		
		final int keyCount = 4;
		final int messageCount = 4; // must be <= 256

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.EdDSA).
			build();
		byte[] m = new byte[] {
			 1,  2,  3,  4,  5,  6,  7,  8,
			 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24,
			25, 26, 27, 28, 29, 30, 31, 32,
			33, 34, 35, 36, 37, 38, 39, 40,
			41, 42, 43, 44, 45, 46, 47, 48,
			49, 50, 51, 52, 53, 54, 55, 56,
			57, 58, 59, 60, 61, 62, 63, 64,
			65, 66, 67, 68, 69, 70, 71, 72,
		};

		Set<Base64URL> sigSet = new HashSet<Base64URL>();

		for (int i=0; i<keyCount; i++) {

			Ed25519Sign.KeyPair tk = Ed25519Sign.KeyPair.newKeyPair();
			OctetKeyPair k = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(tk.getPublicKey())).
				d(Base64URL.encode(tk.getPrivateKey())).
				build();
			Ed25519Signer signer = new Ed25519Signer(k);
			Ed25519Verifier verifier = new Ed25519Verifier(k.toPublicJWK());

			for (int i2=0; i2<messageCount; i2++) {

				// Make message unique
				m[5] = (byte) i2;

				// Sign message then verify signature
				Base64URL s = signer.sign(h, m);
				assertTrue(verifier.verify(h, m, s));

				// Signature should not be same as any previous
				// If this fails, indicates a problem with key gen or signing
				
				assertFalse(sigSet.contains(s), "Same signature generated twice!");				
				sigSet.add(s);

				byte[] sigBytes = s.decode();
//				assertEquals(sigBytes.length, 64);

				// Try flipping each bit in the sig, should cause verification to fail
				for (int sigBitIdx=0; sigBitIdx<64*8; sigBitIdx++) {

					byte mask = (byte) (1 << (sigBitIdx % 8));
					byte[] sigBytesModified = new byte[64];
					System.arraycopy(sigBytes, 0, sigBytesModified, 0, 64);
					sigBytesModified[sigBitIdx/8] ^= mask;
					
					assertFalse(
							verifier.verify(h, m, Base64URL.encode(sigBytesModified)),							
							"bit flip in signature should have caused verify fail"
						);
				}
			}
		}
*/		
		
//		keyGen.initialize(ecSpec, new SecureRandom());
//	    ED_25519("Ed25519", "Ed25519", "1.2.840.10045.3.1.7"),
//	    ED_448("Ed448", "Ed448", "1.3.132.0.10");		
		
/*		
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
*/		
	}
	
	@Test
	public void generateED448Keys() throws Exception {
		showTitle("TEST: generateED448Keys");

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
 	
}