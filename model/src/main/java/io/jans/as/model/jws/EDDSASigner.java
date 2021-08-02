/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2021, Janssen Project
 */
package io.jans.as.model.jws;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;

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

    public static String DEF_BC = "BC";

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
            
            KeyFactorySpi.Ed25519 kf = new KeyFactorySpi.Ed25519();
            
            KeyFactorySpi keyFactorySpi = kf;  
            
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)privateKeySpec).getEncoded());
            
            BCEdDSAPrivateKey privateKey1 = (BCEdDSAPrivateKey)kf.generatePrivate(pki);
            
            byte[] encoding = ASN1OctetString.getInstance(pki.parsePrivateKey()).getOctets();
            
            Ed25519PrivateKeyParameters params = new Ed25519PrivateKeyParameters(encoding);
            
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(params, null);
            
            byte[] encoded7 = privInfo.getEncoded();
            
            RawEncodedKeySpec rawSpec = new RawEncodedKeySpec(encoding); 
            
            byte[] encoded6 = rawSpec.getEncoded();
            
            OpenSSHPrivateKeySpec spec = new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(params));
            
//            protected PrivateKey engineGeneratePrivate(
//                    KeySpec keySpec)
            
            
            byte[] encoded5 = OpenSSHPrivateKeyUtil.encodePrivateKey(params);
            
            byte[] encoded4 = spec.getEncoded();
            
//            BCEdDSAPrivateKey privateKey2 = new BCEdDSAPrivateKey(params);
            
//            kf.
            
            byte[] encoded3 = params.getEncoded();
            
//            ASN1Primitive primitive = ASN1OctetString.fromByteArray(encoding);
            
            byte[] encoded = pki.getEncoded();
            
            byte[] encoded1 = privateKey1.getEncoded();
            
//            ASN1Primitive primitive = ASN1Primitive.fromByteArray(encoding);
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(encoded);
            
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream.create(bOut).writeObject(primitive);
//            ASN1OutputStream.create(bOut).writeObject(params);
            byte[] encoded2 = bOut.toByteArray();
            
            
//            return bOut.toByteArray();            

/*            
            if (privateKeySpec instanceof OpenSSHPrivateKeySpec)
            {
                CipherParameters parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)keySpec).getEncoded());
                if (parameters instanceof Ed25519PrivateKeyParameters)
                {
                    return new BCEdDSAPrivateKey((Ed25519PrivateKeyParameters)parameters);
                }
                throw new IllegalStateException("openssh private key not Ed25519 private key");
            }
*/            
/*

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            try
            {
                return generatePrivate(PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException("encoded key spec not recognized: " + e.getMessage());
            }
        }
        else
        {
            throw new InvalidKeySpecException("key spec not recognized");
        }
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            try
            {
                return generatePublic(SubjectPublicKeyInfo.getInstance(((X509EncodedKeySpec)keySpec).getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException("encoded key spec not recognized: " + e.getMessage());
            }
        }
        else
        {
            throw new InvalidKeySpecException("key spec not recognized");
        }
    }

 */
            
            
            
//            keyFactorySpi.
/*            
            kf.generatePrivate(privateKeySpec);
            
            {
                if (privateKeySpec instanceof OpenSSHPrivateKeySpec)
                {
                    CipherParameters parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)keySpec).getEncoded());
                    if (parameters instanceof Ed25519PrivateKeyParameters)
                    {
                        return new BCEdDSAPrivateKey((Ed25519PrivateKeyParameters)parameters);
                    }
                    throw new IllegalStateException("openssh private key not Ed25519 private key");
                }

                super.engineGeneratePrivate(keySpec);
            }
*/            
            
//            BCEdDSAPrivateKey privateKey = new BCEdDSAPrivateKey(privateKeySpec);
            
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
        } catch (IOException e) {
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
