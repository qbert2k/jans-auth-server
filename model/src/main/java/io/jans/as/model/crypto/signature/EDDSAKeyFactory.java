/**
 * 
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
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.KeyFactory;

/**
 * @author SMan
 *
 */
public class EDDSAKeyFactory  extends KeyFactory<EDDSAPrivateKey, EDDSAPublicKey> {
	
    private SignatureAlgorithm signatureAlgorithm;
    private KeyPair keyPair;

    private EDDSAPrivateKey eddsaPrivateKey;
    private EDDSAPublicKey eddsaPublicKey;
    private Certificate certificate;

    public EDDSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
            throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, CertificateEncodingException {
        if (signatureAlgorithm == null) {
            throw new InvalidParameterException("The signature algorithm cannot be null");
        }

        this.signatureAlgorithm = signatureAlgorithm;
        
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(signatureAlgorithm.getCurve().getAlias());        

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
        keyGen.initialize(ecSpec, new SecureRandom());

        this.keyPair = keyGen.generateKeyPair();
        BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey) keyPair.getPrivate();
        BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyPair.getPublic();
        
        byte [] privateKeyData = privateKey.getEncoded();
        byte [] publicKeyData = publicKey.getEncoded();
        
        this.eddsaPrivateKey = new EDDSAPrivateKey(privateKeyData);
        this.eddsaPublicKey = new EDDSAPublicKey(signatureAlgorithm, publicKeyData, privateKeyData);    

        if (StringUtils.isNotBlank(dnName)) {
            // Create certificate
            GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
            GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
            expiryDate.add(Calendar.YEAR, 1);
            BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate

            X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
            X500Principal principal = new X500Principal(dnName);

            certGen.setSerialNumber(serialNumber);
            certGen.setIssuerDN(principal);
            certGen.setNotBefore(startDate.getTime());
            certGen.setNotAfter(expiryDate.getTime());
            certGen.setSubjectDN(principal); // note: same as issuer
            certGen.setPublicKey(keyPair.getPublic());
            certGen.setSignatureAlgorithm("SHA256WITHECDSA");

            X509Certificate x509Certificate = certGen.generate(privateKey, "BC");
            this.certificate = new Certificate(signatureAlgorithm, x509Certificate);
        }        
    }
    
    public Certificate generateV3Certificate(Date startDate, Date expirationDate, String dnName) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
        // Create certificate
        BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal principal = new X500Principal(dnName);

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(principal);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expirationDate);
        certGen.setSubjectDN(principal); // note: same as issuer
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm(signatureAlgorithm.getAlgorithm());

        X509Certificate x509Certificate = certGen.generate(keyPair.getPrivate(), "BC");
        return new Certificate(signatureAlgorithm, x509Certificate);
    }    

	@Override
	public EDDSAPrivateKey getPrivateKey() {
		return this.eddsaPrivateKey;
	}

	@Override
	public EDDSAPublicKey getPublicKey() {
		return this.eddsaPublicKey;
	}

	@Override
	public Certificate getCertificate() {
		// TODO Auto-generated method stub
		return this.certificate;
	}

}
