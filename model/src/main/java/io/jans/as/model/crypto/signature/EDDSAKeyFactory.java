/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2021, Janssen Project
 */
package io.jans.as.model.crypto.signature;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;

import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.KeyFactory;

/**
 * 
 *
 * @author Sergey Manoylo
 * @version July 23, 2021
 */
public class EDDSAKeyFactory extends KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> {

    public static final String DEF_BC = "BC";
    public static final byte[] Ed448Prefix = Hex.decode("3043300506032b6571033a00");
    public static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");        

    private SignatureAlgorithm signatureAlgorithm;

    private KeyPair keyPair;
    private EDDSAPrivateKey eddsaPrivateKey;
    private EDDSAPublicKey eddsaPublicKey;
    private Certificate certificate;

    /**
     * 
     * @param signatureAlgorithm
     * @param dnName
     * @throws InvalidParameterException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws CertificateEncodingException
     */
    public EDDSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
            throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, CertificateEncodingException {
        if (signatureAlgorithm == null) {
            throw new InvalidParameterException("The signature algorithm cannot be null");
        }
        if (!AlgorithmFamily.ED.equals(signatureAlgorithm.getFamily())) {
            throw new InvalidParameterException("Wrong value of the family of the SignatureAlgorithm");
        }
        try {
            this.signatureAlgorithm = signatureAlgorithm;

            EdDSAParameterSpec edSpec = new EdDSAParameterSpec(signatureAlgorithm.getName());

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(signatureAlgorithm.getName(), DEF_BC);
            keyGen.initialize(edSpec, new SecureRandom());

            this.keyPair = keyGen.generateKeyPair();

            BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey) keyPair.getPrivate();
            BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyPair.getPublic();

            byte[] privateKeyData = privateKey.getEncoded();
            byte[] publicKeyData = publicKey.getEncoded();

            this.eddsaPrivateKey = new EDDSAPrivateKey(signatureAlgorithm, privateKeyData, publicKeyData);
            this.eddsaPublicKey = new EDDSAPublicKey(signatureAlgorithm, publicKeyData);

            if (StringUtils.isNotBlank(dnName)) {
                // Create certificate
                GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
                GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
                expiryDate.add(Calendar.YEAR, 1);
                BigInteger serialNumber = new BigInteger(1024, new SecureRandom()); // serial number for certificate
                X500Name name = new X500Name(dnName);
                JcaX509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(name, serialNumber,
                        startDate.getTime(), expiryDate.getTime(), name, publicKey);
                X509CertificateHolder certHolder = certGen
                        .build(new JcaContentSignerBuilder(signatureAlgorithm.getAlgorithm()).setProvider(DEF_BC)
                                .build(keyPair.getPrivate()));
                X509Certificate cert = new JcaX509CertificateConverter().setProvider(DEF_BC).getCertificate(certHolder);
                this.certificate = new Certificate(signatureAlgorithm, cert);
            }
        } catch (OperatorCreationException e) {
            throw new SignatureException(e);
        } catch (CertificateException e) {
            throw new SignatureException(e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
    }

    /**
     * 
     * @param startDate
     * @param expirationDate
     * @param dnName
     * @return
     * @throws CertificateEncodingException
     * @throws InvalidKeyException
     * @throws IllegalStateException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public Certificate generateV3Certificate(Date startDate, Date expirationDate, String dnName)
            throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException {
        // Create certificate
        Certificate certificate = null;
        try {
            BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyPair.getPublic();
            BigInteger serialNumber = new BigInteger(1024, new SecureRandom()); // serial number for certificate
            X500Name name = new X500Name(dnName);
            JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(name, serialNumber, startDate,
                    expirationDate, name, publicKey);
            X509CertificateHolder certHolder = certGen
                    .build(new JcaContentSignerBuilder(signatureAlgorithm.getAlgorithm()).setProvider(DEF_BC)
                            .build(keyPair.getPrivate()));
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(DEF_BC).getCertificate(certHolder);
            certificate = new Certificate(signatureAlgorithm, cert);
        } catch (OperatorCreationException e) {
            throw new SignatureException(e);
        } catch (CertificateException e) {
            throw new SignatureException(e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
        return certificate;
    }

    /**
     * 
     */
    @Override
    public EDDSAPrivateKey getPrivateKey() {
        return this.eddsaPrivateKey;
    }

    /**
     * 
     */
    @Override
    public EDDSAPublicKey getPublicKey() {
        return this.eddsaPublicKey;
    }

    /**
     * 
     */
    @Override
    public Certificate getCertificate() {
        return this.certificate;
    }

    /**
     * 
     * @param signatureAlgorithm
     * @param decodedPublicKey
     * @return
     * @throws IOException
     * @throws SignatureException 
     */
    public static EDDSAPublicKey createEDDSAPublicKeyFromDecodedKey(SignatureAlgorithm signatureAlgorithm, byte [] decodedPublicKey) throws IOException, SignatureException {
        byte[] encodedPubKey = null; 
        switch(signatureAlgorithm) {
        case EDDSA:
        case ED25519: {
            encodedPubKey = new byte[Ed25519Prefix.length + Ed25519PublicKeyParameters.KEY_SIZE];
            System.arraycopy(Ed25519Prefix, 0, encodedPubKey, 0, Ed25519Prefix.length);
            System.arraycopy(decodedPublicKey, 0, encodedPubKey, Ed25519Prefix.length, decodedPublicKey.length);                
            break;
        }
        case ED448: {
            encodedPubKey = new byte[Ed448Prefix.length + Ed448PublicKeyParameters.KEY_SIZE];
            System.arraycopy(Ed448Prefix, 0, encodedPubKey, 0, Ed448Prefix.length);
            System.arraycopy(decodedPublicKey, 0, encodedPubKey, Ed448Prefix.length, decodedPublicKey.length);                
            break;
        }
        default: {
            throw new SignatureException(String.format("Wrong type of the signature algorithm (SignatureAlgorithm): %s", signatureAlgorithm.toString()));     
        }
        }
        return new EDDSAPublicKey(signatureAlgorithm, encodedPubKey);        
    }
    
    /**
     * 
     * @param signatureAlgorithm
     * @param decodedPrivateKey
     * @param decodedPublicKey
     * @return
     * @throws IOException 
     * @throws SignatureException 
     */
    public static EDDSAPrivateKey createEDDSAPrivateKeyFromDecodedKey(SignatureAlgorithm signatureAlgorithm, byte [] decodedPrivateKey, byte [] decodedPublicKey) throws IOException, SignatureException {
        byte[] encodedPubKey = null; 
        if(decodedPublicKey != null) {
            switch(signatureAlgorithm) {
            case EDDSA:
            case ED25519: {
                encodedPubKey = new byte[Ed25519Prefix.length + Ed25519PublicKeyParameters.KEY_SIZE];
                System.arraycopy(Ed25519Prefix, 0, encodedPubKey, 0, Ed25519Prefix.length);
                System.arraycopy(decodedPublicKey, 0, encodedPubKey, Ed25519Prefix.length, decodedPublicKey.length);                
                break;
            }
            case ED448: {
                encodedPubKey = new byte[Ed448Prefix.length + Ed448PublicKeyParameters.KEY_SIZE];
                System.arraycopy(Ed448Prefix, 0, encodedPubKey, 0, Ed448Prefix.length);
                System.arraycopy(decodedPublicKey, 0, encodedPubKey, Ed448Prefix.length, decodedPublicKey.length);                
                break;
            }
            default: {
                throw new SignatureException(String.format("Wrong type of the signature algorithm (SignatureAlgorithm): %s", signatureAlgorithm.toString()));     
            }
            }
        }
        Ed25519PrivateKeyParameters privKeysParams = new Ed25519PrivateKeyParameters(decodedPrivateKey);
        PrivateKeyInfo privKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privKeysParams, null);
        return new EDDSAPrivateKey(signatureAlgorithm, privKeyInfo.getEncoded(), encodedPubKey);
    }    
    
}
