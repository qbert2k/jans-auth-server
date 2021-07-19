/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.jwe;

import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;

import io.jans.as.model.crypto.encryption.BlockEncryptionAlgorithm;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.RSAPrivateKey;
import io.jans.as.model.exception.InvalidJweException;
import io.jans.as.model.exception.InvalidJwtException;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtClaims;
import io.jans.as.model.jwt.JwtHeader;
import io.jans.as.model.jwt.JwtHeaderName;
import io.jans.as.model.util.SecurityProviderUtility;

/**
 * @author Javier Rojas Blum
 * @version November 20, 2018
 */
public class JweDecrypterImpl extends AbstractJweDecrypter {

    private static final DefaultJWEDecrypterFactory DECRYPTER_FACTORY = new DefaultJWEDecrypterFactory();

    private PrivateKey privateKey;
    private RSAPrivateKey rsaPrivateKey;
    private byte[] sharedSymmetricKey;

    public JweDecrypterImpl(byte[] sharedSymmetricKey) {
        if (sharedSymmetricKey != null) {
            this.sharedSymmetricKey = sharedSymmetricKey.clone();
        }
    }

    public JweDecrypterImpl(RSAPrivateKey rsaPrivateKey) {
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public JweDecrypterImpl(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public Jwe decrypt(String encryptedJwe) throws InvalidJweException {
        try {
            String[] jweParts = encryptedJwe.split("\\.");
            if (jweParts.length != 5) {
                throw new InvalidJwtException("Invalid JWS format.");
            }

            String encodedHeader = jweParts[0];
            String encodedEncryptedKey = jweParts[1];
            String encodedInitializationVector = jweParts[2];
            String encodedCipherText = jweParts[3];
            String encodedIntegrityValue = jweParts[4];

            Jwe jwe = new Jwe();
            jwe.setEncodedHeader(encodedHeader);
            jwe.setEncodedEncryptedKey(encodedEncryptedKey);
            jwe.setEncodedInitializationVector(encodedInitializationVector);
            jwe.setEncodedCiphertext(encodedCipherText);
            jwe.setEncodedIntegrityValue(encodedIntegrityValue);
            jwe.setHeader(new JwtHeader(encodedHeader));

            EncryptedJWT encryptedJwt = EncryptedJWT.parse(encryptedJwe);

            setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm.fromName(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM)));
            setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm.fromName(jwe.getHeader().getClaimAsString(JwtHeaderName.ENCRYPTION_METHOD)));

            final KeyEncryptionAlgorithm keyEncryptionAlgorithm = getKeyEncryptionAlgorithm();
            Key encriptionKey = null;
            if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA1_5 ||
            		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA_OAEP ||
            		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA_OAEP_256 ||
            		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES ||
            		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW ||
            		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES_PLUS_A192KW ||
            		keyEncryptionAlgorithm == KeyEncryptionAlgorithm.ECDH_ES_PLUS_A256KW
            		) {
                encriptionKey = privateKey;
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
                	keyLength = 16;
                	break;
                case A192KW:
                case A192GCMKW:
                	keyLength = 24;            	
                	break;
                case A256KW:
                case A256GCMKW:
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
                encriptionKey = new SecretKeySpec(sharedSymmetricKey, 0, keyLength, "AES");
            } else {
                throw new InvalidJweException("The key encryption algorithm is not supported");
            }
 
            JWEDecrypter decrypter = DECRYPTER_FACTORY.createJWEDecrypter(encryptedJwt.getHeader(), encriptionKey);
            decrypter.getJCAContext().setProvider(SecurityProviderUtility.getInstance());
            encryptedJwt.decrypt(decrypter);

            final SignedJWT signedJWT = encryptedJwt.getPayload().toSignedJWT();
            if (signedJWT != null) {
                final Jwt jwt = Jwt.parse(signedJWT.serialize());
                jwe.setSignedJWTPayload(jwt);
                jwe.setClaims(jwt != null ? jwt.getClaims() : null);
            } else {
                final String base64encodedPayload = encryptedJwt.getPayload().toString();
                jwe.setClaims(new JwtClaims(base64encodedPayload));
            }

            return jwe;
        } catch (Exception e) {
            throw new InvalidJweException(e);
        }
    }
}