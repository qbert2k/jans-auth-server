/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.comp;

import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertNotNull;

import java.security.Key;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.ECDSAPublicKey;
import io.jans.as.model.crypto.signature.EDDSAPrivateKey;
import io.jans.as.model.crypto.signature.EDDSAPublicKey;
import io.jans.as.model.crypto.signature.RSAPublicKey;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.jws.AbstractJwsSigner;
import io.jans.as.model.jws.ECDSASigner;
import io.jans.as.model.jws.EDDSASigner;
import io.jans.as.model.jws.RSASigner;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtType;
import io.jans.as.server.BaseTest;
import io.jans.as.model.exception.SignatureException;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;

/**
 * @author Yuriy Zabrovarnyy
 */
public class JwtCrossCheckTest extends BaseTest {
  
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "RS256_keyId" })
    @Test
    public void rs256CrossCheck(final String dnName,
                              final String keyStoreFile,
                              final String keyStoreSecret,
                              final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.RS256, kid);
    }

    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "RS384_keyId" })
    @Test
    public void rs384CrossCheck(final String dnName,
                                final String keyStoreFile,
                                final String keyStoreSecret,
                                final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.RS384, kid);
    }

    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "RS512_keyId"  })
    @Test
    public void rs512CrossCheck(final String dnName,
                                final String keyStoreFile,
                                final String keyStoreSecret,
                                final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.RS512, kid);
    }

    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ES256_keyId" })
    @Test
    public void es256CrossCheck(final String dnName,
                                final String keyStoreFile,
                                final String keyStoreSecret,
                                final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.ES256, kid);
    }
    
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ES256K_keyId" })
    @Test
    public void es256KCrossCheck(final String dnName,
                                final String keyStoreFile,
                                final String keyStoreSecret,
                                final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.ES256K, kid);
    }    

    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ES384_keyId" })
    @Test
    public void es384CrossCheck(final String dnName,
                                final String keyStoreFile,
                                final String keyStoreSecret,
                                final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.ES384, kid);
    }

    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ES512_keyId" })
    @Test
    public void es512CrossCheck(final String dnName,
                                final String keyStoreFile,
                                final String keyStoreSecret,
                                final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.ES512, kid);
    }
    
    @Parameters({ "dnName", "keyStoreFile", "keyStoreSecret", "ED25519_keyId" })
    @Test
    public void edDsaCrossCheck(final String dnName,
                                final String keyStoreFile,
                                final String keyStoreSecret,
                                final String kid) throws Exception {
        crossCheck(new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName), SignatureAlgorithm.EDDSA, kid);
    }

    /**
     * 
     * @param cryptoProvider
     * @param signatureAlgorithm
     * @param kid
     * @throws Exception
     */
    private void crossCheck(AuthCryptoProvider cryptoProvider, SignatureAlgorithm signatureAlgorithm, String kid) throws Exception {
        System.out.println(String.format("Cross check for %s ...", signatureAlgorithm.getName()));
        final String nimbusJwt = createNimbusJwt(cryptoProvider, kid, signatureAlgorithm);
        validate(nimbusJwt, cryptoProvider, kid, signatureAlgorithm);

        final String oxauthJwt = createOxauthJwt(cryptoProvider, kid, signatureAlgorithm);
        validate(oxauthJwt, cryptoProvider, kid, signatureAlgorithm);
        System.out.println(String.format("Finished cross check for %s.", signatureAlgorithm.getName()));
    }

    /**
     * 
     * @param jwtAsString
     * @param cryptoProvider
     * @param kid
     * @param signatureAlgorithm
     * @throws Exception
     */
    private static void validate(String jwtAsString, AuthCryptoProvider cryptoProvider, String kid, SignatureAlgorithm signatureAlgorithm) throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(jwtAsString);
        Jwt jwt = Jwt.parse(jwtAsString);
        JWSVerifier nimbusVerifier = null;
        AbstractJwsSigner oxauthVerifier = null;
        switch (signatureAlgorithm.getFamily()) {
            case EC:
                final ECKey ecKey = ECKey.load(cryptoProvider.getKeyStore(), kid, cryptoProvider.getKeyStoreSecret().toCharArray());
                final ECPublicKey ecPublicKey = ecKey.toECPublicKey();
                nimbusVerifier = new ECDSAVerifier(ecKey);
                oxauthVerifier = new ECDSASigner(jwt.getHeader().getSignatureAlgorithm(), new ECDSAPublicKey(jwt.getHeader().getSignatureAlgorithm(), ecPublicKey.getW().getAffineX(), ecPublicKey.getW().getAffineY()));
                break;
            case ED:
                Key key = cryptoProvider.getKeyStore().getKey(kid, cryptoProvider.getKeyStoreSecret().toCharArray());
                BCEdDSAPrivateKey bcEdPrivKey = (BCEdDSAPrivateKey)key;
                BCEdDSAPublicKey bcEdPubKey = (BCEdDSAPublicKey) bcEdPrivKey.getPublicKey();
                EDDSAPublicKey edPubKey = new EDDSAPublicKey(jwt.getHeader().getSignatureAlgorithm(), bcEdPubKey.getEncoded());
                OctetKeyPair okp = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(edPubKey.getPublicKeyDecoded())).build();
                nimbusVerifier = new Ed25519Verifier(okp);
                oxauthVerifier = new EDDSASigner(jwt.getHeader().getSignatureAlgorithm(), new EDDSAPublicKey(jwt.getHeader().getSignatureAlgorithm(), bcEdPubKey.getEncoded()));
                break;
            case RSA:
                RSAKey rsaKey = RSAKey.load(cryptoProvider.getKeyStore(), kid, cryptoProvider.getKeyStoreSecret().toCharArray());
                final java.security.interfaces.RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
                nimbusVerifier = new RSASSAVerifier(rsaKey);
                oxauthVerifier = new RSASigner(signatureAlgorithm, new RSAPublicKey(rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent()));
                break;
            default:
                throw new SignatureException(String.format("wrong type of the Algorithm Family: %s", signatureAlgorithm.getFamily().toString()));
        }

        assertNotNull(nimbusVerifier);
        assertNotNull(oxauthVerifier);

        // Nimbus
        assertTrue(signedJWT.verify(nimbusVerifier));

        // oxauth cryptoProvider
        boolean validJwt = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), kid,
                null, null, jwt.getHeader().getSignatureAlgorithm());
        assertTrue(validJwt);

        // oxauth verifier
        assertTrue(oxauthVerifier.validate(jwt));
    }

    /**
     * 
     * @param cryptoProvider
     * @param kid
     * @param signatureAlgorithm
     * @return
     * @throws Exception
     */
    private static String createNimbusJwt(AuthCryptoProvider cryptoProvider, String kid, SignatureAlgorithm signatureAlgorithm) throws Exception {
        final AlgorithmFamily family = signatureAlgorithm.getFamily();

        JWSSigner signer = null;
        switch (family) {
            case RSA:
                signer = new RSASSASigner(RSAKey.load(cryptoProvider.getKeyStore(), kid, cryptoProvider.getKeyStoreSecret().toCharArray()));
                break;
            case EC:
                signer = new com.nimbusds.jose.crypto.ECDSASigner(ECKey.load(cryptoProvider.getKeyStore(), kid, cryptoProvider.getKeyStoreSecret().toCharArray()));
                break;
            case ED:
                Key key = cryptoProvider.getKeyStore().getKey(kid, cryptoProvider.getKeyStoreSecret().toCharArray());
                BCEdDSAPrivateKey bcEdPrivKey = (BCEdDSAPrivateKey)key;
                BCEdDSAPublicKey bcEdPubKey = (BCEdDSAPublicKey) bcEdPrivKey.getPublicKey();
                EDDSAPrivateKey edPrivKey = new EDDSAPrivateKey(signatureAlgorithm, bcEdPrivKey.getEncoded(), bcEdPubKey.getEncoded());                
                OctetKeyPair okp = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(edPrivKey.getPublicKeyDecoded())).d(Base64URL.encode(edPrivKey.getPrivateKeyDecoded())).build();
                signer = new Ed25519Signer(okp);                
                break;
            default:
                throw new SignatureException(String.format("wrong type of the Algorithm Family: %s", family.toString()));
        }

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("1202.d50a4eeb-ab5d-474b-aaaf-e4aa47bc54a5")
                .issuer("1202.d50a4eeb-ab5d-474b-aaaf-e4aa47bc54a5")
                .expirationTime(new Date(1575559276888000L))
                .issueTime(new Date(1575559276888000L))
                .audience("https://gomer-vbox/jans-auth/restv1/token")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(signatureAlgorithm.getJwsAlgorithm()).keyID(kid).build(),
                claimsSet);

        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private static String createOxauthJwt(AuthCryptoProvider cryptoProvider, String kid, SignatureAlgorithm algorithm) throws Exception {
        Jwt jwt = new Jwt();

        jwt.getHeader().setKeyId(kid);
        jwt.getHeader().setType(JwtType.JWT);
        jwt.getHeader().setAlgorithm(algorithm);

        jwt.getClaims().setSubjectIdentifier("1202.d50a4eeb-ab5d-474b-aaaf-e4aa47bc54a5");
        jwt.getClaims().setIssuer("1202.d50a4eeb-ab5d-474b-aaaf-e4aa47bc54a5");
        jwt.getClaims().setExpirationTime(new Date(1575559276888000L));
        jwt.getClaims().setIssuedAt(new Date(1575559276888000L));
        jwt.getClaims().setAudience("https://gomer-vbox/jans-auth/restv1/token");

        String signature = cryptoProvider.sign(jwt.getSigningInput(), jwt.getHeader().getKeyId(), null, algorithm);
        jwt.setEncodedSignature(signature);
        return jwt.toString();
    }

    @SuppressWarnings("unused")
    private static String getKeyIdByAlgorithm(SignatureAlgorithm algorithm, Use use, AuthCryptoProvider cryptoProvider) throws KeyStoreException {
        final List<String> aliases = cryptoProvider.getKeys();
        for (String keyId : aliases) {
            if (keyId.endsWith(use.getParamName()  + "_" + algorithm.getName().toLowerCase())) {
                return keyId;
            }
        }
        return null;
    }
}
