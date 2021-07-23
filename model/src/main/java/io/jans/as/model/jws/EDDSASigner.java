/**
 * 
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
 * @author SMan
 *
 */
public class EDDSASigner extends AbstractJwsSigner {

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
        if(!signatureAlgorithm.getFamily().equals(AlgorithmFamily.ED)) {
            throw new SignatureException(String.format("Wrong value of the signature algorithm: %s", signatureAlgorithm.getFamily().toString()));
        }
        if (eddsaPrivateKey == null) {
            throw new SignatureException("The EDDSA private key is null");
        }
        if (signingInput == null) {
            throw new SignatureException("The signing input is null");
        }
        
        {
            org.bouncycastle.crypto.signers.Ed25519phSigner signer; // = new 
        }
        
        
        try {
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(eddsaPrivateKey.getPrivateKeyData());
//            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(eddsaPublicKey.getPublicKeyData());
			
	        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(signatureAlgorithm.getName());
	        
	        BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey)keyFactory.generatePrivate(privateKeySpec);
//	        BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey)keyFactory.generatePublic(publicKeySpec);	        
	        
	        Signature signer = Signature.getInstance(signatureAlgorithm.getName(), "BC");
	        signer.initSign(privateKey);
	        signer.update(signingInput.getBytes());
	        
	        byte [] signature = signer.sign();
	        
/*	        
            if (AlgorithmFamily.EC.equals(getSignatureAlgorithm().getFamily())) {
            	int signatureLenght = ECDSA.getSignatureByteArrayLength(JWSAlgorithm.parse(getSignatureAlgorithm().getName()));
                signature = ECDSA.transcodeSignatureToConcat(signature, signatureLenght);
            }
*/            	        
	        
	        String signatureBase64 = Base64Util.base64urlencode(signature);

	        return signatureBase64;  
		} catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
		} catch (NoSuchProviderException e) {
            throw new SignatureException(e);			
		} catch (InvalidKeySpecException e) {
            throw new SignatureException(e);			
		} catch (InvalidKeyException e) {
            throw new SignatureException(e);			
		}
        
/*        
        BCEdDSAPrivateKey privateKey_private = (BCEdDSAPrivateKey)keyFactory.generatePrivate(pkcs8EncodedKeySpec_private);
        BCEdDSAPublicKey publicKey_1 = (BCEdDSAPublicKey)keyFactory.generatePublic(publicKeySpec);	             
        
        
    	private EDDSAPrivateKey eddsaPrivateKey;	
    	private EDDSAPublicKey eddsaPublicKey;        
        
        
        byte [] privateKeyData = privateKey.getEncoded();
        byte [] publicKeyData = publicKey.getEncoded();        
        
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("Ed25519");
//        org.bouncycastle.jcajce.spec.RawEncodedKeySpec pkcs8EncodedKeySpec = new org.bouncycastle.jcajce.spec.RawEncodedKeySpec(publicKeySpecData);
        
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec_private = new PKCS8EncodedKeySpec(privateKeyData);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyData);        
        
        
        try {
            // ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(getSignatureAlgorithm().getCurve().getName());
        	ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(getSignatureAlgorithm().getCurve().getAlias());
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(ecdsaPrivateKey.getD(), ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            Signature signer = Signature.getInstance(getSignatureAlgorithm().getAlgorithm(), "BC");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(Util.UTF8_STRING_ENCODING));

            byte[] signature = signer.sign();
            if (AlgorithmFamily.EC.equals(getSignatureAlgorithm().getFamily())) {
            	int signatureLenght = ECDSA.getSignatureByteArrayLength(JWSAlgorithm.parse(getSignatureAlgorithm().getName()));
                signature = ECDSA.transcodeSignatureToConcat(signature, signatureLenght);
            }

            return Base64Util.base64urlencode(signature);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException(e);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        } catch (NoSuchProviderException e) {
            throw new SignatureException(e);
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }        
*/		
/*		
        if (getSignatureAlgorithm() == null) {
            throw new SignatureException("The signature algorithm is null");
        }
        if (eddsaPrivateKey == null) {
            throw new SignatureException("The EDDSA private key is null");
        }
        if (signingInput == null) {
            throw new SignatureException("The signing input is null");
        }
        try {
        	//	eyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519", "BC");
            // ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(getSignatureAlgorithm().getCurve().getName());

        	ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(getSignatureAlgorithm().getCurve().getAlias());
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(eddsaPrivateKey.getD(), ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            Signature signer = Signature.getInstance(getSignatureAlgorithm().getAlgorithm(), "BC");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(Util.UTF8_STRING_ENCODING));

            byte[] signature = signer.sign();
            if (AlgorithmFamily.EC.equals(getSignatureAlgorithm().getFamily())) {
            	int signatureLenght = ECDSA.getSignatureByteArrayLength(JWSAlgorithm.parse(getSignatureAlgorithm().getName()));
                signature = ECDSA.transcodeSignatureToConcat(signature, signatureLenght);
            }

            return Base64Util.base64urlencode(signature);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException(e);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        } catch (NoSuchProviderException e) {
            throw new SignatureException(e);
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
        
        
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
	        
	        Ed25519PublicKeyParameters params = new Ed25519PublicKeyParameters(publicKeyData, 0);
	        
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
//	        
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
*/        
//		return null;
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
        if(!signatureAlgorithm.getFamily().equals(AlgorithmFamily.ED)) {
            throw new SignatureException(String.format("Wrong value of the signature algorithm: %s", signatureAlgorithm.getFamily().toString()));
        }        
        if (eddsaPublicKey == null) {
            throw new SignatureException("The EDDSA public key is null");
        }
        if (signingInput == null) {
            throw new SignatureException("The signing input is null");
        }
        
        try {
        	
//            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(eddsaPrivateKey.getPrivateKeyData());
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(eddsaPublicKey.getPublicKeyData());
        	
//        	PKCS8EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(eddsaPublicKey.getPublicKeyData());        	
			
	        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(signatureAlgorithm.getName());
	        
//	        BCEdDSAPrivateKey privateKey = (BCEdDSAPrivateKey)keyFactory.generatePrivate(privateKeySpec);
	        BCEdDSAPublicKey publicKey = (BCEdDSAPublicKey)keyFactory.generatePublic(publicKeySpec);	        
	        
            Signature virifier = Signature.getInstance(signatureAlgorithm.getName(), "BC");
            virifier.initVerify(publicKey);
            virifier.update(signingInput.getBytes());
            
            boolean res = virifier.verify(Base64Util.base64urldecode(signature));
            
            virifier.initVerify(publicKey);
            virifier.update(signingInput.getBytes());
            
            res = virifier.verify(Base64Util.base64urldecode(signature));

            virifier.initVerify(publicKey);
            virifier.update(signingInput.getBytes());
            
            res = virifier.verify(Base64Util.base64urldecode(signature));
            
//            res = virifier.verify(Base64Util.base64urldecode(signature));
//            res = virifier.verify(Base64Util.base64urldecode(signature));
            
            return res;
            
            //return virifier.verify(Base64Util.base64urldecode(signature));
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
        
/*        
        String algorithm;
        String curve;
        switch (getSignatureAlgorithm()) {
            case ES256:
                algorithm = "SHA256WITHECDSA";
                curve = "P-256";
                break;
            case ES256K:
                algorithm = "SHA256WITHECDSA";
                curve = "secp256k1";
                break;
            case ES384:
                algorithm = "SHA384WITHECDSA";
                curve = "P-384";
                break;
            case ES512:
                algorithm = "SHA512WITHECDSA";
                curve = "P-521";
                break;
            default:
                throw new SignatureException("Unsupported signature algorithm");
        }
*/
/*        
        SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
        try {
            byte[] sigBytes = Base64Util.base64urldecode(signature);
            if (AlgorithmFamily.EC.equals(getSignatureAlgorithm().getFamily())) {
                sigBytes = ECDSA.transcodeSignatureToDER(sigBytes);
            }
            byte[] sigInBytes = signingInput.getBytes(Util.UTF8_STRING_ENCODING);

            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(signatureAlgorithm.getCurve().getAlias());
            ECPoint pointQ = ecSpec.getCurve().createPoint(ecdsaPublicKey.getX(), ecdsaPublicKey.getY());

            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(pointQ, ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            Signature sig = Signature.getInstance(signatureAlgorithm.getAlgorithm(), "BC");
            sig.initVerify(publicKey);
            sig.update(sigInBytes);
            return sig.verify(sigBytes);
        } catch (InvalidKeySpecException e) {
            throw new SignatureException(e);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        } catch (NoSuchProviderException e) {
            throw new SignatureException(e);
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
*/        
	}

}
