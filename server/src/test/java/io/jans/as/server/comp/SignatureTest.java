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
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.Key;
import io.jans.as.model.crypto.KeyFactory;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
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
import io.jans.as.server.BaseTest;

/**
 * @author Javier Rojas Blum Date: 12.03.2012
 */
@SuppressWarnings("deprecation")
public class SignatureTest extends BaseTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static String DEF_CERTIFICATE_OWN = "CN=Test CA Certificate";
    private static String DEF_INPUT = "Hello World!";

    /**
     * 
     * @throws Exception
     */
    @Test
    public void generateRS256Keys() throws Exception {
        showTitle("TEST: generateRS256Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;        

        KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(signatureAlgorithm,
                DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

        RSAPrivateKey privateKey = key.getPrivateKey();
        RSAPublicKey publicKey = key.getPublicKey();
        Certificate certificate = key.getCertificate();

        System.out.println(key);

        String signingInput = DEF_INPUT;
        RSASigner rsaSigner1 = new RSASigner(signatureAlgorithm, privateKey);
        String signature = rsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        RSASigner rsaSigner2 = new RSASigner(signatureAlgorithm, publicKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));
        RSASigner rsaSigner3 = new RSASigner(signatureAlgorithm, certificate);
        assertTrue(rsaSigner3.validateSignature(signingInput, signature));

        keyFactory = new RSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
        RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        rsaSigner2 = new RSASigner(signatureAlgorithm, publicKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));

        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner4 = new RSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(rsaSigner4.validateSignature(signingInput, signature));

        assertFalse(rsaSigner4.validateSignature(signingInput, signature));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner5 = new RSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(rsaSigner5.validateSignature(signingInput, signature));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }
    
    /**
     * 
     * @param dnName
     * @param keyStoreFile
     * @param keyStoreSecret
     * @param kid
     * @throws Exception
     */
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "RS256_keyId" })    
    @Test
    public void readRS256Keys(final String dnName,
            final String keyStoreFile,
            final String keyStoreSecret,
            final String kid) throws Exception {
        
        showTitle("TEST: readRS256Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
        
        TestKeys testKeys = loadTestKeys(signatureAlgorithm, keyStoreFile, keyStoreSecret, dnName,
                kid);

        java.security.interfaces.RSAPrivateKey privateKey = (java.security.interfaces.RSAPrivateKey) testKeys.privateKey;
        java.security.interfaces.RSAPublicKey publicKey = (java.security.interfaces.RSAPublicKey) testKeys.publicKey;
        java.security.cert.Certificate certificate = testKeys.certificate;
        
        RSAPrivateKey privKey = new RSAPrivateKey(signatureAlgorithm, privateKey.getModulus(), privateKey.getPrivateExponent());
        RSAPublicKey pubKey = new RSAPublicKey(publicKey.getModulus(), publicKey.getPublicExponent());
        Certificate cert = new Certificate(signatureAlgorithm, (X509Certificate)certificate);

        String signingInput = DEF_INPUT;
        RSASigner rsaSigner1 = new RSASigner(signatureAlgorithm, privKey);
        String signature = rsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        RSASigner rsaSigner2 = new RSASigner(signatureAlgorithm, pubKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));
        RSASigner rsaSigner3 = new RSASigner(signatureAlgorithm, cert);
        assertTrue(rsaSigner3.validateSignature(signingInput, signature));

        KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
        RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        rsaSigner2 = new RSASigner(signatureAlgorithm, pubKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));

        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner4 = new RSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(rsaSigner4.validateSignature(signingInput, signature));

        assertFalse(rsaSigner4.validateSignature(signingInput, signature));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner5 = new RSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(rsaSigner5.validateSignature(signingInput, signature));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));        
    }

    @Test
    public void generateRS384Keys() throws Exception {
        showTitle("TEST: generateRS384Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS384;        

        KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(signatureAlgorithm,
                DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

        RSAPrivateKey privateKey = key.getPrivateKey();
        RSAPublicKey publicKey = key.getPublicKey();
        Certificate certificate = key.getCertificate();

        System.out.println(key);

        String signingInput = DEF_INPUT;
        RSASigner rsaSigner1 = new RSASigner(signatureAlgorithm, privateKey);
        String signature = rsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        RSASigner rsaSigner2 = new RSASigner(signatureAlgorithm, publicKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));
        RSASigner rsaSigner3 = new RSASigner(signatureAlgorithm, certificate);
        assertTrue(rsaSigner3.validateSignature(signingInput, signature));

        keyFactory = new RSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
        RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        rsaSigner2 = new RSASigner(signatureAlgorithm, publicKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));

        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner4 = new RSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(rsaSigner4.validateSignature(signingInput, signature));

        assertFalse(rsaSigner4.validateSignature(signingInput, signature));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner5 = new RSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(rsaSigner5.validateSignature(signingInput, signature));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }

    /**
     * 
     * @param dnName
     * @param keyStoreFile
     * @param keyStoreSecret
     * @param kid
     * @throws Exception
     */
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "RS384_keyId" })
    @Test
    public void readRS384Keys(final String dnName,
            final String keyStoreFile,
            final String keyStoreSecret,
            final String kid) throws Exception {
        showTitle("TEST: readRS384Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS384;
        
        TestKeys testKeys = loadTestKeys(signatureAlgorithm, keyStoreFile, keyStoreSecret, dnName,
                kid);

        java.security.interfaces.RSAPrivateKey privateKey = (java.security.interfaces.RSAPrivateKey) testKeys.privateKey;
        java.security.interfaces.RSAPublicKey publicKey = (java.security.interfaces.RSAPublicKey) testKeys.publicKey;
        java.security.cert.Certificate certificate = testKeys.certificate;
        
        RSAPrivateKey privKey = new RSAPrivateKey(signatureAlgorithm, privateKey.getModulus(), privateKey.getPrivateExponent());
        RSAPublicKey pubKey = new RSAPublicKey(publicKey.getModulus(), publicKey.getPublicExponent());
        Certificate cert = new Certificate(signatureAlgorithm, (X509Certificate)certificate);

        String signingInput = DEF_INPUT;
        RSASigner rsaSigner1 = new RSASigner(signatureAlgorithm, privKey);
        String signature = rsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        RSASigner rsaSigner2 = new RSASigner(signatureAlgorithm, pubKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));
        RSASigner rsaSigner3 = new RSASigner(signatureAlgorithm, cert);
        assertTrue(rsaSigner3.validateSignature(signingInput, signature));

        KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
        RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        rsaSigner2 = new RSASigner(signatureAlgorithm, pubKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));

        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner4 = new RSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(rsaSigner4.validateSignature(signingInput, signature));

        assertFalse(rsaSigner4.validateSignature(signingInput, signature));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner5 = new RSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(rsaSigner5.validateSignature(signingInput, signature));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }

    @Test
    public void generateRS512Keys() throws Exception {
        showTitle("TEST: generateRS512Keys");

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS512;
        
        KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(signatureAlgorithm,
                DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> key = keyFactory.getKey();

        RSAPrivateKey privateKey = key.getPrivateKey();
        RSAPublicKey publicKey = key.getPublicKey();
        Certificate certificate = key.getCertificate();

        System.out.println(key);

        String signingInput = DEF_INPUT;
        RSASigner rsaSigner1 = new RSASigner(signatureAlgorithm, privateKey);
        String signature = rsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        RSASigner rsaSigner2 = new RSASigner(signatureAlgorithm, publicKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));
        RSASigner rsaSigner3 = new RSASigner(signatureAlgorithm, certificate);
        assertTrue(rsaSigner3.validateSignature(signingInput, signature));

        keyFactory = new RSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
        RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        rsaSigner2 = new RSASigner(signatureAlgorithm, publicKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));

        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner4 = new RSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(rsaSigner4.validateSignature(signingInput, signature));

        assertFalse(rsaSigner4.validateSignature(signingInput, signature));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner5 = new RSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(rsaSigner5.validateSignature(signingInput, signature));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }
    
    /**
     * 
     * @param dnName
     * @param keyStoreFile
     * @param keyStoreSecret
     * @param kid
     * @throws Exception
     */
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "RS512_keyId" })
    @Test
    public void readRS512Keys(final String dnName,
            final String keyStoreFile,
            final String keyStoreSecret,
            final String kid) throws Exception {
        showTitle("TEST: readRS512Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS512;        
        
        TestKeys testKeys = loadTestKeys(signatureAlgorithm, keyStoreFile, keyStoreSecret, dnName,
                kid);

        java.security.interfaces.RSAPrivateKey privateKey = (java.security.interfaces.RSAPrivateKey) testKeys.privateKey;
        java.security.interfaces.RSAPublicKey publicKey = (java.security.interfaces.RSAPublicKey) testKeys.publicKey;
        java.security.cert.Certificate certificate = testKeys.certificate;
        
        RSAPrivateKey privKey = new RSAPrivateKey(signatureAlgorithm, privateKey.getModulus(), privateKey.getPrivateExponent());
        RSAPublicKey pubKey = new RSAPublicKey(publicKey.getModulus(), publicKey.getPublicExponent());
        Certificate cert = new Certificate(signatureAlgorithm, (X509Certificate)certificate);

        String signingInput = DEF_INPUT;
        RSASigner rsaSigner1 = new RSASigner(signatureAlgorithm, privKey);
        String signature = rsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        RSASigner rsaSigner2 = new RSASigner(signatureAlgorithm, pubKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));
        RSASigner rsaSigner3 = new RSASigner(signatureAlgorithm, cert);
        assertTrue(rsaSigner3.validateSignature(signingInput, signature));

        KeyFactory<RSAPrivateKey, RSAPublicKey> keyFactory = new RSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<RSAPrivateKey, RSAPublicKey> keyWrong = keyFactory.getKey();
        RSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        rsaSigner2 = new RSASigner(signatureAlgorithm, pubKey);
        assertTrue(rsaSigner2.validateSignature(signingInput, signature));

        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner4 = new RSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(rsaSigner4.validateSignature(signingInput, signature));

        assertFalse(rsaSigner4.validateSignature(signingInput, signature));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        RSASigner rsaSigner5 = new RSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(rsaSigner5.validateSignature(signingInput, signature));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(rsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(rsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }

    @Test
    public void generateES256Keys() throws Exception {
        showTitle("TEST: generateES256Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES256;

        KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(signatureAlgorithm,
                DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

        ECDSAPrivateKey privateKey = key.getPrivateKey();
        ECDSAPublicKey publicKey = key.getPublicKey();
        Certificate certificate = key.getCertificate();

        System.out.println(key);

        String signingInput = DEF_INPUT;
        ECDSASigner ecdsaSigner1 = new ECDSASigner(signatureAlgorithm, privateKey);
        String signature = ecdsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        ECDSASigner ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, publicKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
        ECDSASigner ecdsaSigner3 = new ECDSASigner(signatureAlgorithm, certificate);
        assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
                .getParameterSpec(signatureAlgorithm.getCurve().getAlias());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey.getD(), ecSpec);

        ECPoint pointQ = ecSpec.getCurve().createPoint(publicKey.getX(), publicKey.getY());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

        java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
        BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
        BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

        ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
        ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

        assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP256R1Curve.class);
        assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP256R1Curve.class);

        assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP256R1Curve().getFieldSize());
        assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP256R1Curve().getFieldSize());

        keyFactory = new ECDSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

        ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, publicKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner4 = new ECDSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner5 = new ECDSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }
    
    /**
     * 
     * @param dnName
     * @param keyStoreFile
     * @param keyStoreSecret
     * @param kid
     * @throws Exception
     */
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ES256_keyId" })        
    @Test
    public void readES256Keys(final String dnName,
            final String keyStoreFile,
            final String keyStoreSecret,
            final String kid) throws Exception {
        showTitle("TEST: generateES256Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES256;        
        
        TestKeys testKeys = loadTestKeys(signatureAlgorithm, keyStoreFile, keyStoreSecret, dnName,
                kid);
        
        java.security.interfaces.ECPrivateKey privateKey = (java.security.interfaces.ECPrivateKey) testKeys.privateKey;
        java.security.interfaces.ECPublicKey publicKey = (java.security.interfaces.ECPublicKey) testKeys.publicKey;        
        java.security.cert.Certificate certificate = testKeys.certificate;
        
        ECDSAPrivateKey privKey = new ECDSAPrivateKey(signatureAlgorithm, privateKey.getS()); 
        ECDSAPublicKey pubKey = new ECDSAPublicKey(signatureAlgorithm, publicKey.getW().getAffineX(), publicKey.getW().getAffineY());        
        Certificate cert = new Certificate(signatureAlgorithm, (X509Certificate)certificate);
        
        String signingInput = DEF_INPUT;
        ECDSASigner ecdsaSigner1 = new ECDSASigner(signatureAlgorithm, privKey);
        String signature = ecdsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        ECDSASigner ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, pubKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
        ECDSASigner ecdsaSigner3 = new ECDSASigner(signatureAlgorithm, cert);
        assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
                .getParameterSpec(signatureAlgorithm.getCurve().getAlias());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privKey.getD(), ecSpec);

        ECPoint pointQ = ecSpec.getCurve().createPoint(pubKey.getX(), pubKey.getY());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

        java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
        BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
        BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

        ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
        ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

        assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP256R1Curve.class);
        assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP256R1Curve.class);

        assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP256R1Curve().getFieldSize());
        assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP256R1Curve().getFieldSize());

        KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

        ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, pubKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner4 = new ECDSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner5 = new ECDSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));        
    }

    @Test
    public void generateES256KKeys() throws Exception {
        showTitle("TEST: generateES256KKeys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES256K;          

        KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(signatureAlgorithm,
                DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

        ECDSAPrivateKey privateKey = key.getPrivateKey();
        ECDSAPublicKey publicKey = key.getPublicKey();
        Certificate certificate = key.getCertificate();

        System.out.println(key);

        String signingInput = DEF_INPUT;
        ECDSASigner ecdsaSigner1 = new ECDSASigner(signatureAlgorithm, privateKey);
        String signature = ecdsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        ECDSASigner ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, publicKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
        ECDSASigner ecdsaSigner3 = new ECDSASigner(signatureAlgorithm, certificate);
        assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
                .getParameterSpec(signatureAlgorithm.getCurve().getAlias());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey.getD(), ecSpec);

        ECPoint pointQ = ecSpec.getCurve().createPoint(publicKey.getX(), publicKey.getY());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

        java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
        BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
        BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

        ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
        ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

        assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP256K1Curve.class);
        assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP256K1Curve.class);

        assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP256K1Curve().getFieldSize());
        assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP256K1Curve().getFieldSize());

        keyFactory = new ECDSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

        ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, publicKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner4 = new ECDSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner5 = new ECDSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }
    
    /**
     * 
     * @param dnName
     * @param keyStoreFile
     * @param keyStoreSecret
     * @param kid
     * @throws Exception
     */
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ES256K_keyId" })        
    @Test
    public void readES256KKeys(final String dnName,
            final String keyStoreFile,
            final String keyStoreSecret,
            final String kid) throws Exception {
        showTitle("TEST: readES256KKeys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES256K;        
        
        TestKeys testKeys = loadTestKeys(signatureAlgorithm, keyStoreFile, keyStoreSecret, dnName,
                kid);
        
        java.security.interfaces.ECPrivateKey privateKey = (java.security.interfaces.ECPrivateKey) testKeys.privateKey;
        java.security.interfaces.ECPublicKey publicKey = (java.security.interfaces.ECPublicKey) testKeys.publicKey;        
        java.security.cert.Certificate certificate = testKeys.certificate;
        
        ECDSAPrivateKey privKey = new ECDSAPrivateKey(signatureAlgorithm, privateKey.getS()); 
        ECDSAPublicKey pubKey = new ECDSAPublicKey(signatureAlgorithm, publicKey.getW().getAffineX(), publicKey.getW().getAffineY());        
        Certificate cert = new Certificate(signatureAlgorithm, (X509Certificate)certificate);
        
        String signingInput = DEF_INPUT;
        ECDSASigner ecdsaSigner1 = new ECDSASigner(signatureAlgorithm, privKey);
        String signature = ecdsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        ECDSASigner ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, pubKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
        ECDSASigner ecdsaSigner3 = new ECDSASigner(signatureAlgorithm, cert);
        assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
                .getParameterSpec(signatureAlgorithm.getCurve().getAlias());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privKey.getD(), ecSpec);

        ECPoint pointQ = ecSpec.getCurve().createPoint(pubKey.getX(), pubKey.getY());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

        java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
        BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
        BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

        ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
        ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));
        
        assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP256K1Curve.class);
        assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP256K1Curve.class);        

        assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP256K1Curve().getFieldSize());
        assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP256K1Curve().getFieldSize());

        KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

        ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, pubKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner4 = new ECDSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner5 = new ECDSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));        
    }    

    @Test
    public void generateES384Keys() throws Exception {
        showTitle("TEST: generateES384Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES384;

        KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(signatureAlgorithm,
                DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> key = keyFactory.getKey();

        ECDSAPrivateKey privateKey = key.getPrivateKey();
        ECDSAPublicKey publicKey = key.getPublicKey();
        Certificate certificate = key.getCertificate();

        System.out.println(key);

        String signingInput = DEF_INPUT;
        ECDSASigner ecdsaSigner1 = new ECDSASigner(signatureAlgorithm, privateKey);
        String signature = ecdsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        ECDSASigner ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, publicKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
        ECDSASigner ecdsaSigner3 = new ECDSASigner(signatureAlgorithm, certificate);
        assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
                .getParameterSpec(signatureAlgorithm.getCurve().getAlias());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey.getD(), ecSpec);

        ECPoint pointQ = ecSpec.getCurve().createPoint(publicKey.getX(), publicKey.getY());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

        java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
        BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
        BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

        ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
        ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));

        assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP384R1Curve.class);
        assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP384R1Curve.class);

        assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP384R1Curve().getFieldSize());
        assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP384R1Curve().getFieldSize());

        keyFactory = new ECDSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

        ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, publicKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner4 = new ECDSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner5 = new ECDSASigner(signatureAlgorithm, certificateWrong);
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner5.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner5.validateSignature(signingInputWrong, signatureWrong));
    }
    
    /**
     * 
     * @param dnName
     * @param keyStoreFile
     * @param keyStoreSecret
     * @param kid
     * @throws Exception
     */
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ES384_keyId" })        
    @Test
    public void readES384Keys(final String dnName,
            final String keyStoreFile,
            final String keyStoreSecret,
            final String kid) throws Exception {
        showTitle("TEST: readES384Keys");
        
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES384;
        
        TestKeys testKeys = loadTestKeys(signatureAlgorithm, keyStoreFile, keyStoreSecret, dnName,
                kid);
        
        java.security.interfaces.ECPrivateKey privateKey = (java.security.interfaces.ECPrivateKey) testKeys.privateKey;
        java.security.interfaces.ECPublicKey publicKey = (java.security.interfaces.ECPublicKey) testKeys.publicKey;        
        java.security.cert.Certificate certificate = testKeys.certificate;
        
        ECDSAPrivateKey privKey = new ECDSAPrivateKey(signatureAlgorithm, privateKey.getS()); 
        ECDSAPublicKey pubKey = new ECDSAPublicKey(signatureAlgorithm, publicKey.getW().getAffineX(), publicKey.getW().getAffineY());        
        Certificate cert = new Certificate(signatureAlgorithm, (X509Certificate)certificate);
        
        String signingInput = DEF_INPUT;
        ECDSASigner ecdsaSigner1 = new ECDSASigner(signatureAlgorithm, privKey);
        String signature = ecdsaSigner1.generateSignature(signingInput);
        assertTrue(signature.length() > 0);
        ECDSASigner ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, pubKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));
        ECDSASigner ecdsaSigner3 = new ECDSASigner(signatureAlgorithm, cert);
        assertTrue(ecdsaSigner3.validateSignature(signingInput, signature));

        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
                .getParameterSpec(signatureAlgorithm.getCurve().getAlias());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privKey.getD(), ecSpec);

        ECPoint pointQ = ecSpec.getCurve().createPoint(pubKey.getX(), pubKey.getY());
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

        java.security.KeyFactory keyFactoryNative = java.security.KeyFactory.getInstance("ECDSA", "BC");
        BCECPrivateKey privateKeyNative = (BCECPrivateKey) keyFactoryNative.generatePrivate(privateKeySpec);
        BCECPublicKey publicKeyNative = (BCECPublicKey) keyFactoryNative.generatePublic(publicKeySpec);

        ECNamedCurveParameterSpec ecSpecPrivateKey = (ECNamedCurveParameterSpec) privateKeyNative.getParameters();
        ECNamedCurveParameterSpec ecSpecPrublicKey = (ECNamedCurveParameterSpec) publicKeyNative.getParameters();

        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrivateKey.getName()));
        assertTrue(signatureAlgorithm.getCurve().getAlias().equals(ecSpecPrublicKey.getName()));
        
        assertTrue(ecSpecPrivateKey.getCurve().getClass() == SecP384R1Curve.class);
        assertTrue(ecSpecPrublicKey.getCurve().getClass() == SecP384R1Curve.class);        

        assertTrue(ecSpecPrivateKey.getCurve().getFieldSize() == new SecP384R1Curve().getFieldSize());
        assertTrue(ecSpecPrublicKey.getCurve().getFieldSize() == new SecP384R1Curve().getFieldSize());

        KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> keyFactory = new ECDSAKeyFactory(signatureAlgorithm, DEF_CERTIFICATE_OWN);

        Key<ECDSAPrivateKey, ECDSAPublicKey> keyWrong = keyFactory.getKey();

        ECDSAPublicKey publicKeyWrong = keyWrong.getPublicKey();
        Certificate certificateWrong = keyWrong.getCertificate();

        byte[] signatureArray = Base64Util.base64urldecode(signature);
        signatureArray[signatureArray.length - 1] = (byte) (~signatureArray[signatureArray.length - 1]);
        String signatureWrong = Base64Util.base64urlencode(signatureArray);

        String signingInputWrong = signingInput + 'z';

        ecdsaSigner2 = new ECDSASigner(signatureAlgorithm, pubKey);
        assertTrue(ecdsaSigner2.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner2.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner2.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner4 = new ECDSASigner(signatureAlgorithm, publicKeyWrong);
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));

        assertFalse(ecdsaSigner4.validateSignature(signingInput, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signature));
        assertFalse(ecdsaSigner4.validateSignature(signingInput, signatureWrong));
        assertFalse(ecdsaSigner4.validateSignature(signingInputWrong, signatureWrong));

        ECDSASigner ecdsaSigner5 = new ECDSASigner(signatureAlgorithm, certificateWrong);
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

    /**
     * 
     * @author SMan
     *
     */
    private static class TestKeys {
        public java.security.Key privateKey;
        public java.security.PublicKey publicKey;
        public java.security.cert.Certificate certificate;
    };

    /**
     * 
     * @return
     * @throws Exception 
     */
    private TestKeys loadTestKeys(SignatureAlgorithm signatureAlgorithm, String keyStore, String keyStoreSecret, String dName,
            String keyID) throws Exception {
        
        TestKeys testKeys = new TestKeys();
        
        AuthCryptoProvider authCryptoProvider = new AuthCryptoProvider(keyStore, keyStoreSecret, dName);
        java.security.Key privateKey = authCryptoProvider.getKeyStore().getKey(keyID,
                authCryptoProvider.getKeyStoreSecret().toCharArray());
        java.security.PublicKey publicKey = authCryptoProvider.getKeyStore().getCertificate(keyID).getPublicKey();
        java.security.cert.Certificate certificate = authCryptoProvider.getKeyStore().getCertificate(keyID);
        
        testKeys.privateKey = privateKey;
        testKeys.publicKey = publicKey;
        testKeys.certificate = certificate;

        return testKeys;
    }

    /**
     * 
     * @param signatureAlgorithmTest
     * @param keyStore
     * @param keyStoreSecret
     * @param dName
     * @param keyID
     */
    private void loadKey(SignatureAlgorithm signatureAlgorithm, String keyStore, String keyStoreSecret, String dName,
            String keyID) {
        try {
            AuthCryptoProvider authCryptoProvider = new AuthCryptoProvider(keyStore, keyStoreSecret, dName);
            java.security.Key privKey = authCryptoProvider.getKeyStore().getKey(keyID,
                    authCryptoProvider.getKeyStoreSecret().toCharArray());
            java.security.PublicKey pubKey = authCryptoProvider.getKeyStore().getCertificate(keyID).getPublicKey();
            if (signatureAlgorithm.getFamily() == AlgorithmFamily.RSA) {
                java.security.interfaces.RSAPrivateKey rsaPrivateKey = (java.security.interfaces.RSAPrivateKey) privKey;
                java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) pubKey;

                java.security.cert.Certificate certificate = authCryptoProvider.getKeyStore().getCertificate(keyID);

                String privateStr = Base64Util.base64urlencode(rsaPrivateKey.getEncoded());
                String publicStr = Base64Util.base64urlencode(rsaPublicKey.getEncoded());

                String certStr = Base64Util.base64urlencode(certificate.getEncoded());

                System.out.println("------------------------- >>");
                System.out.println("keyStore    = " + keyStore);
                System.out.println("signatureAlgorithm.getName()    = " + signatureAlgorithm.getName());
                System.out.println("signatureAlgorithm.getAlgorithm() = " + signatureAlgorithm.getAlgorithm());
                System.out.println("keyID       = " + keyID);
                System.out.println("privateStr = " + privateStr);
                System.out.println("publicStr  = " + publicStr);
                System.out.println("certStr     = " + certStr);
                System.out.println("------------------------- <<");

            } else if (signatureAlgorithm.getFamily() == AlgorithmFamily.EC) {
                ECPrivateKey ecPrivateKey = (ECPrivateKey) privKey;
                ECPublicKey ecPublicKey = (ECPublicKey) pubKey;

                java.security.cert.Certificate certificate = authCryptoProvider.getKeyStore().getCertificate(keyID);

                BigInteger privateS = ecPrivateKey.getS();

                BigInteger publicX = ecPublicKey.getW().getAffineX();
                BigInteger publicY = ecPublicKey.getW().getAffineY();

                String privateSStr = Base64Util.base64urlencode(privateS.toByteArray());
                String publicXStr = Base64Util.base64urlencode(publicX.toByteArray());
                String publicYStr = Base64Util.base64urlencode(publicY.toByteArray());

                String certStr = Base64Util.base64urlencode(certificate.getEncoded());

                System.out.println("------------------------- >>");
                System.out.println("keyStore    = " + keyStore);
                System.out.println("signatureAlgorithm.getName()    = " + signatureAlgorithm.getName());
                System.out.println("signatureAlgorithm.getAlgorithm() = " + signatureAlgorithm.getAlgorithm());
                System.out.println("keyID       = " + keyID);
                System.out.println("privateSStr = " + privateSStr);
                System.out.println("publicXStr  = " + publicXStr);
                System.out.println("publicYStr  = " + publicYStr);
                System.out.println("certStr     = " + certStr);
                System.out.println("------------------------- <<");

            } else if (signatureAlgorithm.getFamily() == AlgorithmFamily.ED) {
                BCEdDSAPrivateKey bcEdPrivKey = (BCEdDSAPrivateKey) privKey;
                BCEdDSAPublicKey bcEdPublicKey = (BCEdDSAPublicKey) pubKey;

                EDDSAPrivateKey edPrivKey = new EDDSAPrivateKey(signatureAlgorithm, bcEdPrivKey.getEncoded(),
                        bcEdPublicKey.getEncoded());
                EDDSAPublicKey edPublicKey = new EDDSAPublicKey(signatureAlgorithm, bcEdPublicKey.getEncoded());

                String privateStr = Base64Util.base64urlencode(edPrivKey.getPrivateKeyDecoded());
                String publicStr = Base64Util.base64urlencode(edPublicKey.getPublicKeyDecoded());

                java.security.cert.Certificate certificate = authCryptoProvider.getKeyStore().getCertificate(keyID);

                String certStr = Base64Util.base64urlencode(certificate.getEncoded());

                System.out.println("------------------------- >>");
                System.out.println("keyStore    = " + keyStore);
                System.out.println("signatureAlgorithm.getName()    = " + signatureAlgorithm.getName());
                System.out.println("signatureAlgorithm.getAlgorithm() = " + signatureAlgorithm.getAlgorithm());
                System.out.println("keyID       = " + keyID);
                System.out.println("privateStr  = " + privateStr);
                System.out.println("publicStr   = " + publicStr);
                System.out.println("certStr     = " + certStr);
                System.out.println("------------------------- <<");
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    @Test
    public void aLoadKeysTemp() {

        String clientKeyStoreFile = "profiles/ce.gluu.info/client_keystore.jks";
        String keyStoreFile = "conf/keystore.jks";

        String clientKeyStoreSecret = "secret";
        String dName = "CN=Jans Auth CA Certificates";

        /// ----------------------------------------------

        loadKey(SignatureAlgorithm.RS256, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "6fb1859a-54d9-47c6-a293-92ce2cee63e0");
        loadKey(SignatureAlgorithm.RS384, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "a68c61dd-f8f6-4faf-855b-fbbb8bee028a");
        loadKey(SignatureAlgorithm.RS512, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "79d12e66-0baa-4b59-8a8b-bd3164260bf5");

        loadKey(SignatureAlgorithm.ES256, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "a8b62c9d-65ea-4384-a491-e52924c4a0e3");
        loadKey(SignatureAlgorithm.ES256K, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "356c7a32-3ea2-4c7a-9d12-fe8f80732ec9");
        loadKey(SignatureAlgorithm.ES384, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "0b1a019f-fcfb-4d3d-981b-16b45355dfdf");
        loadKey(SignatureAlgorithm.ES512, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "07c917ef-943f-4a9a-961c-d3cba28c81d5");

        loadKey(SignatureAlgorithm.ED25519, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "77cd3480-0dd4-4617-bfc7-523062566aa3");
        loadKey(SignatureAlgorithm.ED448, clientKeyStoreFile, clientKeyStoreSecret, dName,
                "f7c79092-43dc-472e-90f6-1644b7788450");

        /// ----------------------------------------------

        loadKey(SignatureAlgorithm.RS256, keyStoreFile, clientKeyStoreSecret, dName,
                "15d79fe5-55de-4e3d-a6dd-9ce15e07b382");
        loadKey(SignatureAlgorithm.RS384, keyStoreFile, clientKeyStoreSecret, dName,
                "ffb5bb6e-0c86-4ee5-8fb1-1366b6eca189");
        loadKey(SignatureAlgorithm.RS512, keyStoreFile, clientKeyStoreSecret, dName,
                "13a6a2cb-3bc3-4cae-82e9-e5a516288815");

        loadKey(SignatureAlgorithm.ES256, keyStoreFile, clientKeyStoreSecret, dName,
                "e98f2a7c-0ff2-4313-939a-0b6f41d9cfd6");
        loadKey(SignatureAlgorithm.ES256K, keyStoreFile, clientKeyStoreSecret, dName,
                "3df98442-e895-49c2-a855-09c0948c9d98");
        loadKey(SignatureAlgorithm.ES384, keyStoreFile, clientKeyStoreSecret, dName,
                "bc3dca3f-9358-4fba-968e-fadc5adc5c11");
        loadKey(SignatureAlgorithm.ES512, keyStoreFile, clientKeyStoreSecret, dName,
                "2f081371-3593-4bd0-87de-4b3b743ec742");

        loadKey(SignatureAlgorithm.ED25519, keyStoreFile, clientKeyStoreSecret, dName,
                "da89a229-24cb-4c01-bd96-e33342223841");
        loadKey(SignatureAlgorithm.ED448, keyStoreFile, clientKeyStoreSecret, dName,
                "b2221043-d4bf-41b4-9f41-27c6f3ad4d8b");

            /// ----------------------------------------------
/*            
              ES256("ES256", AlgorithmFamily.EC, "SHA256WITHECDSA",
              EllipticEdvardsCurve.P_256, JWSAlgorithm.ES256), ES256K("ES256K",
              AlgorithmFamily.EC, "SHA256WITHECDSA", EllipticEdvardsCurve.P_256K,
              JWSAlgorithm.ES256K), ES384("ES384", AlgorithmFamily.EC, "SHA384WITHECDSA",
              EllipticEdvardsCurve.P_384, JWSAlgorithm.ES384), ES512("ES512",
              AlgorithmFamily.EC, "SHA512WITHECDSA", EllipticEdvardsCurve.P_521,
              JWSAlgorithm.ES512),
              
              PS256("PS256", AlgorithmFamily.RSA, "SHA256withRSAandMGF1",
              JWSAlgorithm.PS256), PS384("PS384", AlgorithmFamily.RSA,
              "SHA384withRSAandMGF1", JWSAlgorithm.PS384), PS512("PS512",
              AlgorithmFamily.RSA, "SHA512withRSAandMGF1", JWSAlgorithm.PS512),
              
              ED25519("Ed25519", AlgorithmFamily.ED, "Ed25519", JWSAlgorithm.EdDSA),
              ED448("Ed448", AlgorithmFamily.ED, "Ed448", JWSAlgorithm.EdDSA),
              EDDSA("EdDSA", AlgorithmFamily.ED, "Ed25519", JWSAlgorithm.EdDSA);
             

            
              AuthCryptoProvider authCryptoProvider = new
              AuthCryptoProvider(clientKeyStoreFile, clientKeyStoreSecret, dName);
              
              { String kid = "a8b62c9d-65ea-4384-a491-e52924c4a0e3"; Key key =
              authCryptoProvider.getKeyStore().getKey(kid,
              authCryptoProvider.getKeyStoreSecret().toCharArray()); ECPrivateKey
              ecPrivateKey = (ECPrivateKey) key; PublicKey pubKey =
              authCryptoProvider.getKeyStore().getCertificate(kid).getPublicKey();
              ECPublicKey ecPublicKey = (ECPublicKey) pubKey;
              
              Certificate certificate =
              authCryptoProvider.getKeyStore().getCertificate(kid);
              
              BigInteger privateS = ecPrivateKey.getS();
              
              BigInteger publicX = ecPublicKey.getW().getAffineX(); BigInteger publicY =
              ecPublicKey.getW().getAffineY();
              
              String res = "";
              
              String privateSArray = Base64Util.base64urlencode(privateS.toByteArray());
              String publicXArray = Base64Util.base64urlencode(publicX.toByteArray());
              String publicYArray = Base64Util.base64urlencode(publicY.toByteArray());
              
              System.out.println("kid = " + kid); System.out.println("privateSArray = " +
              privateSArray); System.out.println("publicXArray = " + publicXArray);
              System.out.println("publicYArray = " + publicYArray);
              
              }
              
              SignatureAlgorithm signatureAlgorithmTest = SignatureAlgorithm.ES256;
              
              switch(signatureAlgorithmTest) { case ES256: { String kid =
              "a8b62c9d-65ea-4384-a491-e52924c4a0e3"; Key key =
              authCryptoProvider.getKeyStore().getKey(kid,
              authCryptoProvider.getKeyStoreSecret().toCharArray()); ECPrivateKey
              ecPrivateKey = (ECPrivateKey) key; PublicKey pubKey =
              authCryptoProvider.getKeyStore().getCertificate(kid).getPublicKey();
              ECPublicKey ecPublicKey = (ECPublicKey) pubKey;
              
              Certificate certificate =
              authCryptoProvider.getKeyStore().getCertificate(kid);
              
              BigInteger privateS = ecPrivateKey.getS();
              
              BigInteger publicX = ecPublicKey.getW().getAffineX(); BigInteger publicY =
              ecPublicKey.getW().getAffineY();
              
              String res = "";
              
              String privateSArray = Base64Util.base64urlencode(privateS.toByteArray());
              String publicXArray = Base64Util.base64urlencode(publicX.toByteArray());
              String publicYArray = Base64Util.base64urlencode(publicY.toByteArray());
              
              System.out.println("kid = " + kid); System.out.println("privateSArray = " +
              privateSArray); System.out.println("publicXArray = " + publicXArray);
              System.out.println("publicYArray = " + publicYArray);
              
              break; } case ES256K: { break; } default: { return; } }
             
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        
          final String ec1JwkJson1 = "" +
          "{ \"kty\":\"EC\", \"crv\":\"P-256\", \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\", \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\", \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\", \"use\":\"enc\", \"kid\":\"3\" }"
          ;
          
          final String ec1JwkJson1 = "kty": "EC"
          
          { "kty": "EC", "crv": "P-256", "x":
          "APS72gkIPSdfdxGQfdKRScs5BRFrIXMfkbd-M-b32CXU", "y":
          "akmZ3aHwJks4EpkSoVSwFZMtoPkLqhSbKqae2hWqnRY", "d":
          "WaXjTYk_7wWXiE3Lh2Y5xXssGz4WAou0GmhGM2ZXf9A", "use": "enc", "kid": "3" }
          
          // Ec // BCEdDSAPrivateKey bcEdPrivKey = (BCEdDSAPrivateKey)key; //
          BCEdDSAPublicKey bcEdPubKey = (BCEdDSAPublicKey) bcEdPrivKey.getPublicKey();
          
         

        
          clientKeyStoreFile=profiles/ce.gluu.info/client_keystore.jks;
          clientKeyStoreSecret=secret
         

        
          ED25519("Ed25519", AlgorithmFamily.ED, "Ed25519", JWSAlgorithm.EdDSA),
          ED448("Ed448", AlgorithmFamily.ED, "Ed448", JWSAlgorithm.EdDSA),
          EDDSA("EdDSA", AlgorithmFamily.ED, "Ed25519", JWSAlgorithm.EdDSA);
          
          ES256("ES256", AlgorithmFamily.EC, "SHA256WITHECDSA",
          EllipticEdvardsCurve.P_256, JWSAlgorithm.ES256), ES256K("ES256K",
          AlgorithmFamily.EC, "SHA256WITHECDSA", EllipticEdvardsCurve.P_256K,
          JWSAlgorithm.ES256K),
 */        
    }

}
