/**
 * 
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
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

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
    
/*    
    static ASN1ObjectIdentifier getAlgorithmOID(
            String algorithmName)
        {
            algorithmName = Strings.toUpperCase(algorithmName);
            
            if (algorithms.containsKey(algorithmName))
            {
                return (ASN1ObjectIdentifier)algorithms.get(algorithmName);
            }
            
            return new ASN1ObjectIdentifier(algorithmName);
        }
    */

    public EDDSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
            throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, CertificateEncodingException {
        if (signatureAlgorithm == null) {
            throw new InvalidParameterException("The signature algorithm cannot be null");
        }

        this.signatureAlgorithm = signatureAlgorithm;
        
        EdDSAParameterSpec ecSpec = new EdDSAParameterSpec("Ed25519");        

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
			try {
	            // Create certificate
	            GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
	            GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
	            expiryDate.add(Calendar.YEAR, 1);
	            BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate
	            
	            X500Name principal = new X500Name(dnName);
	            
//	             ASN1ObjectIdentifier sigOID = X509Util.getAlgorithmOID(signatureAlgorithm);	            
	            
//	            ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(curveName);
	            
//	            AlgorithmIdentifier ai = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.1"));
//	            AlgorithmIdentifier ai = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.3.1.7"));
//	            AlgorithmIdentifier ai = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.15.1"));
	            AlgorithmIdentifier ai = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.101.112"));
	            
	            ASN1ObjectIdentifier oi = new ASN1ObjectIdentifier("1.3.101.112");
	            String id = oi.getId();
	            byte[] encoded = oi.getEncoded();
	            
	            ASN1Encodable encodable = null; 
	            
//	            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ai, encodable);
	            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ai, publicKeyData);	            
	            
	            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(principal, serialNumber, startDate.getTime(), expiryDate.getTime(), principal,
	            		subjectPublicKeyInfo);
				
				X509CertificateHolder cert = certBuilder.build(new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(keyPair.getPrivate()));
	            X509Certificate x509cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
	            
	            this.certificate = new Certificate(signatureAlgorithm, x509cert);
				
			} catch (OperatorCreationException e) {
				throw new SignatureException(e);
			} catch (CertificateException e) {
				throw new SignatureException(e);
			} catch (IOException e) {
				throw new SignatureException(e);				
			} 
            
/*            
            certBuilder.build(signer)
            
            X509v3CertificateBuilder(org.bouncycastle.asn1.x500.X500Name issuer, java.math.BigInteger serial, java.util.Date notBefore, java.util.Date notAfter, org.bouncycastle.asn1.x500.X500Name subject, org.bouncycastle.asn1.x509.SubjectPublicKeyInfo publicKeyInfo)
            Create a builder for a version 3 certificate.            
            
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            	      owner, new BigInteger(64, random), notBefore, notAfter, owner, keypair.getPublic());            

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            certGen.setSerialNumber(serialNumber);
            certGen.setIssuerDN(principal);
            certGen.setNotBefore(startDate.getTime());
            certGen.setNotAfter(expiryDate.getTime());
            certGen.setSubjectDN(principal); // note: same as issuer
            certGen.setPublicKey(keyPair.getPublic());
            certGen.setSignatureAlgorithm(signatureAlgorithm.getAlgorithm());

            X509Certificate x509Certificate = certGen.generate(privateKey, "BC");
            this.certificate = new Certificate(signatureAlgorithm, x509Certificate);
*/            
        }        
    }
    
    public Certificate generateV3Certificate(Date startDate, Date expirationDate, String dnName) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
        // Create certificate
    	
        BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey) keyPair.getPublic();
        
        byte [] publicKeyData = publicKey.getEncoded();   
        
        Certificate certificate = null;
    	
		try {
            // Create certificate
            BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate
            
            X500Name principal = new X500Name(dnName);
            
            AlgorithmIdentifier ai = new AlgorithmIdentifier(new ASN1ObjectIdentifier("Ed25519"));
            
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ai, publicKeyData);
            
            X509v1CertificateBuilder certBuilder = new X509v1CertificateBuilder(principal, serialNumber, startDate, expirationDate, principal,
            		subjectPublicKeyInfo);
			
			X509CertificateHolder cert = certBuilder.build(new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(keyPair.getPrivate()));
            X509Certificate x509cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
            
            certificate = new Certificate(signatureAlgorithm, x509cert);
			
		} catch (OperatorCreationException e) {
			throw new SignatureException(e);
		} catch (CertificateException e) {
			throw new SignatureException(e);
		} 
		
		return certificate;
    	
/*    	
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
*/        
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
