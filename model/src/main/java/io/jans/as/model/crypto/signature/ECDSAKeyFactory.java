/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.crypto.signature;

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
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.KeyFactory;

/**
 * Factory to create asymmetric Public and Private Keys for the Elliptic Curve
 * Digital Signature Algorithm (ECDSA)
 *
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public class ECDSAKeyFactory extends KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> {

    public static final String DEF_BC = "BC";

    private SignatureAlgorithm signatureAlgorithm;
    private KeyPair keyPair;

    private ECDSAPrivateKey ecdsaPrivateKey;
    private ECDSAPublicKey ecdsaPublicKey;
    private Certificate certificate;

    public ECDSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
            throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, CertificateEncodingException {
        if (signatureAlgorithm == null) {
            throw new InvalidParameterException("The signature algorithm cannot be null");
        }

        try {
            this.signatureAlgorithm = signatureAlgorithm;

            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(signatureAlgorithm.getCurve().getAlias());

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyGen.initialize(ecSpec, new SecureRandom());

            this.keyPair = keyGen.generateKeyPair();
            BCECPrivateKey privateKeySpec = (BCECPrivateKey) keyPair.getPrivate();
            BCECPublicKey publicKeySpec = (BCECPublicKey) keyPair.getPublic();

            BigInteger x = publicKeySpec.getQ().getXCoord().toBigInteger();
            BigInteger y = publicKeySpec.getQ().getYCoord().toBigInteger();
            BigInteger d = privateKeySpec.getD();

            this.ecdsaPrivateKey = new ECDSAPrivateKey(signatureAlgorithm, d);
            this.ecdsaPublicKey = new ECDSAPublicKey(signatureAlgorithm, x, y);

            if (StringUtils.isNotBlank(dnName)) {
                // Create certificate
                GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
                GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
                expiryDate.add(Calendar.YEAR, 1);
                BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate
                X500Name name = new X500Name(dnName);
                JcaX509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(name, serialNumber,
                        startDate.getTime(), expiryDate.getTime(), name, keyPair.getPublic());
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

    public Certificate generateV3Certificate(Date startDate, Date expirationDate, String dnName)
            throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException {
        // Create certificate
        Certificate certificate = null;
        try {
            BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyPair.getPublic();
            BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate
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

    @Override
    public ECDSAPrivateKey getPrivateKey() {
        return ecdsaPrivateKey;
    }

    @Override
    public ECDSAPublicKey getPublicKey() {
        return ecdsaPublicKey;
    }

    @Override
    public Certificate getCertificate() {
        return certificate;
    }
}