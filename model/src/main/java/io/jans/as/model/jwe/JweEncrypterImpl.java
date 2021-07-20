/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.jwe;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import io.jans.as.model.crypto.encryption.BlockEncryptionAlgorithm;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.exception.InvalidJweException;
import io.jans.as.model.exception.InvalidJwtException;
import io.jans.as.model.jwt.JwtHeader;
import io.jans.as.model.jwt.JwtType;
import io.jans.as.model.util.Base64Util;

/**
 * @author Javier Rojas Blum
 * @version November 20, 2018
 */
public class JweEncrypterImpl extends AbstractJweEncrypter {

    private byte[] sharedSymmetricKey;
    private String sharedSymmetricPassword;
    
    private PublicKey publicKey;
    private ECKey ecKey;

    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm, BlockEncryptionAlgorithm blockEncryptionAlgorithm, byte[] sharedSymmetricKey) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        if (sharedSymmetricKey != null) {
            this.sharedSymmetricKey = sharedSymmetricKey.clone();
        }
    }
    
    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm, BlockEncryptionAlgorithm blockEncryptionAlgorithm, String sharedSymmetricPassword) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        this.sharedSymmetricPassword = sharedSymmetricPassword;
    }

    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm, BlockEncryptionAlgorithm blockEncryptionAlgorithm, PublicKey publicKey) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        this.publicKey = publicKey;
    }
    
    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm, BlockEncryptionAlgorithm blockEncryptionAlgorithm, ECKey ecKey) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        this.ecKey = ecKey;
    }    

    public JWEEncrypter createJweEncrypter() throws JOSEException, InvalidJweException, NoSuchAlgorithmException {
        final KeyEncryptionAlgorithm keyEncryptionAlgorithm = getKeyEncryptionAlgorithm();
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA1_5 || 
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA_OAEP || 
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA_OAEP_256) {
            return new RSAEncrypter(new RSAKey.Builder((RSAPublicKey) publicKey).build());
        }
        else if(keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES || 
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW ||        
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES_PLUS_A192KW ||        		
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES_PLUS_A256KW) {
        	return new ECDHEncrypter(new ECKey.Builder(ecKey).build());
        }
        else if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A128KW ||
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A256KW ||
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A192KW ||
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A128GCMKW ||        		
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A192GCMKW ||        		
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A256GCMKW        		
        		) {
            if (sharedSymmetricKey == null) {
                throw new InvalidJweException("The shared symmetric key is null");
            }
            
            int keyLength;            
            
            switch(keyEncryptionAlgorithm) {
            case A128KW:
            case A128GCMKW:
            case PBES2_HS256_PLUS_A128KW:
            	keyLength = 16;
            	break;
            case A192KW:
            case A192GCMKW:
            case PBES2_HS384_PLUS_A192KW:            	
            	keyLength = 24;            	
            	break;
            case A256KW:
            case A256GCMKW:
            case PBES2_HS384_PLUS_A256KW:            	
            	keyLength = 32;            	
            	break;
            default:
                throw new InvalidJweException(String.format("Wrong value of the key encryption algorithm: " + keyEncryptionAlgorithm.toString()));            	
            }
            
            if (sharedSymmetricKey.length != keyLength) {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                sharedSymmetricKey = sha.digest(sharedSymmetricKey);
                sharedSymmetricKey = Arrays.copyOf(sharedSymmetricKey, keyLength);
            }
            return new AESEncrypter(sharedSymmetricKey);
        } 
        else if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW ||        		
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW ||        		
        		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A256KW) {
        	return new PasswordBasedEncrypter(sharedSymmetricPassword, 16, 8192);
        }
        else {
            throw new InvalidJweException("The key encryption algorithm is not supported");
        }
    }

    public static Payload createPayload(Jwe jwe) throws ParseException, InvalidJwtException, UnsupportedEncodingException {
        if (jwe.getSignedJWTPayload() != null) {
            return new Payload(SignedJWT.parse(jwe.getSignedJWTPayload().toString()));
        }
        return new Payload(Base64Util.base64urlencode(jwe.getClaims().toJsonString().getBytes("UTF-8")));
    }

    @Override
    public Jwe encrypt(Jwe jwe) throws InvalidJweException {
        try {
            JWEEncrypter encrypter = createJweEncrypter();

            if (jwe.getSignedJWTPayload() != null) {
                jwe.getHeader().setContentType(JwtType.JWT);
            }
            
            System.out.println("jwe.getHeader().toJsonObject() = " + JWEHeader.parse(jwe.getHeader().toJsonObject().toString()));
            
            JWEObject jweObject = new JWEObject(JWEHeader.parse(jwe.getHeader().toJsonObject().toString()), createPayload(jwe));

            jweObject.encrypt(encrypter);
            String encryptedJwe = jweObject.serialize();

            String[] jweParts = encryptedJwe.split("\\.");
            if (jweParts.length != 5) {
                throw new InvalidJwtException("Invalid JWS format.");
            }

            String encodedHeader = jweParts[0];
            String encodedEncryptedKey = jweParts[1];
            String encodedInitializationVector = jweParts[2];
            String encodedCipherText = jweParts[3];
            String encodedIntegrityValue = jweParts[4];

            jwe.setEncodedHeader(encodedHeader);
            jwe.setEncodedEncryptedKey(encodedEncryptedKey);
            jwe.setEncodedInitializationVector(encodedInitializationVector);
            jwe.setEncodedCiphertext(encodedCipherText);
            jwe.setEncodedIntegrityValue(encodedIntegrityValue);
            jwe.setHeader(new JwtHeader(encodedHeader));

            return jwe;
        } catch (Exception e) {
            throw new InvalidJweException(e);
        }
    }
}