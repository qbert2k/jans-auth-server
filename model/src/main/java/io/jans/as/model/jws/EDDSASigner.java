/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2021, Janssen Project
 */
package io.jans.as.model.jws;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;

import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.EDDSAPrivateKey;
import io.jans.as.model.crypto.signature.EDDSAPublicKey;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.util.Base64Util;

/**
 * 
 *
 * @author Sergey Manoylo
 * @version July 23, 2021
 */
public class EDDSASigner extends AbstractJwsSigner {

    public static final String DEF_BC = "BC";

    private EDDSAPrivateKey eddsaPrivateKey;
    private EDDSAPublicKey eddsaPublicKey;

    /**
     * 
     * @param signatureAlgorithm
     * @param eddsaPrivateKey
     */
    public EDDSASigner(SignatureAlgorithm signatureAlgorithm, EDDSAPrivateKey eddsaPrivateKey) {
        super(signatureAlgorithm);
        this.eddsaPrivateKey = eddsaPrivateKey;
    }

    /**
     * 
     * @param signatureAlgorithm
     * @param eddsaPublicKey
     */
    public EDDSASigner(SignatureAlgorithm signatureAlgorithm, EDDSAPublicKey eddsaPublicKey) {
        super(signatureAlgorithm);
        this.eddsaPublicKey = eddsaPublicKey;
    }

    /**
     * 
     * @param signatureAlgorithm
     * @param certificate
     */
    public EDDSASigner(SignatureAlgorithm signatureAlgorithm, Certificate certificate) {
        super(signatureAlgorithm);
        this.eddsaPublicKey = certificate.getEddsaPublicKey();
    }

    /**
     *
     */
    @Override
    public String generateSignature(String signingInput) throws SignatureException {
        SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
        if (signatureAlgorithm == null) {
            throw new SignatureException("The signature algorithm is null");
        }
        if (!signatureAlgorithm.getFamily().equals(AlgorithmFamily.ED)) {
            throw new SignatureException(String.format("Wrong value of the signature algorithm: %s",
                    signatureAlgorithm.getFamily().toString()));
        }
        if (eddsaPrivateKey == null) {
            throw new SignatureException("The EDDSA private key is null");
        }
        if (signingInput == null) {
            throw new SignatureException("The signing input is null");
        }
        try {
            PKCS8EncodedKeySpec privateKeySpec = eddsaPrivateKey.getPrivateKeySpec();
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(signatureAlgorithm.getName());
            BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            Signature signer = Signature.getInstance(signatureAlgorithm.getName(), DEF_BC);
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes());
            byte[] signature = signer.sign();
            return Base64Util.base64urlencode(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        } catch (NoSuchProviderException e) {
            throw new SignatureException(e);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException(e);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        }
    }


    /**
     * 
     */
    @Override
    public boolean validateSignature(String signingInput, String signature) throws SignatureException {
        SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
        if (signatureAlgorithm == null) {
            throw new SignatureException("The signature algorithm is null");
        }
        if (!signatureAlgorithm.getFamily().equals(AlgorithmFamily.ED)) {
            throw new SignatureException(String.format("Wrong value of the signature algorithm: %s",
                    signatureAlgorithm.getFamily().toString()));
        }
        if (eddsaPublicKey == null) {
            throw new SignatureException("The EDDSA public key is null");
        }
        if (signingInput == null) {
            throw new SignatureException("The signing input is null");
        }
        try {
            X509EncodedKeySpec publicKeySpec = eddsaPublicKey.getPublicKeySpec();
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(signatureAlgorithm.getName());
            BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            Signature virifier = Signature.getInstance(signatureAlgorithm.getName(), "BC");
            virifier.initVerify(publicKey);
            virifier.update(signingInput.getBytes());
            return virifier.verify(Base64Util.base64urldecode(signature));
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        } catch (NoSuchProviderException e) {
            throw new SignatureException(e);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException(e);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } catch (IllegalArgumentException e) {
            throw new SignatureException(e);
        }
    }
}
