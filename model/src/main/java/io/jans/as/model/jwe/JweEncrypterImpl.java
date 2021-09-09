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
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import io.jans.as.model.crypto.encryption.BlockEncryptionAlgorithm;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
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

    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm,
            BlockEncryptionAlgorithm blockEncryptionAlgorithm, byte[] sharedSymmetricKey) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        if (sharedSymmetricKey != null) {
            this.sharedSymmetricKey = sharedSymmetricKey.clone();
        }
    }

    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm,
            BlockEncryptionAlgorithm blockEncryptionAlgorithm, String sharedSymmetricPassword) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        this.sharedSymmetricPassword = sharedSymmetricPassword;
    }

    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm,
            BlockEncryptionAlgorithm blockEncryptionAlgorithm, PublicKey publicKey) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        this.publicKey = publicKey;
    }

    public JweEncrypterImpl(KeyEncryptionAlgorithm keyEncryptionAlgorithm,
            BlockEncryptionAlgorithm blockEncryptionAlgorithm, ECKey ecKey) {
        super(keyEncryptionAlgorithm, blockEncryptionAlgorithm);
        this.ecKey = ecKey;
    }

    public JWEEncrypter createJweEncrypter() throws JOSEException, InvalidJweException, NoSuchAlgorithmException {
        final KeyEncryptionAlgorithm keyEncryptionAlgorithm = getKeyEncryptionAlgorithm();
        if(keyEncryptionAlgorithm == null) {
            throw new InvalidJweException("KeyEncryptionAlgorithm isn't defined");
        }
        AlgorithmFamily algorithmFamily = keyEncryptionAlgorithm.getFamily();
        switch(algorithmFamily) {
        case RSA: {
            return new RSAEncrypter(new RSAKey.Builder((RSAPublicKey) publicKey).build());            
        }
        case EC: {
            return new ECDHEncrypter(new ECKey.Builder(ecKey).build());            
        }
        case AES:
        case DIR: {
            if (sharedSymmetricKey == null) {
                throw new InvalidJweException("The shared symmetric key is null");
            }
            int keyLength;
            switch (keyEncryptionAlgorithm) {
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
                throw new InvalidJweException(String
                        .format("Wrong value of the key encryption algorithm: " + keyEncryptionAlgorithm.toString()));
            }
            if (sharedSymmetricKey.length != keyLength) {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                sharedSymmetricKey = sha.digest(sharedSymmetricKey);
                sharedSymmetricKey = Arrays.copyOf(sharedSymmetricKey, keyLength);
            }
            if (AlgorithmFamily.AES.equals(algorithmFamily)) {
                return new AESEncrypter(sharedSymmetricKey);            
            }
            else if(AlgorithmFamily.DIR.equals(algorithmFamily)) {
                return new DirectEncrypter(sharedSymmetricKey);
            }
        }
        case PASSW: {
            return new PasswordBasedEncrypter(sharedSymmetricPassword, 16, 8192);            
        }
        default: {
            throw new InvalidJweException("wrong AlgorithmFamily value");
        }
        }
/*        
    case DIR: {
        if (sharedSymmetricKey == null) {
            throw new InvalidJweException("The shared symmetric key is null");
        }
        int keyLength;
        switch (keyEncryptionAlgorithm) {
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
            throw new InvalidJweException(String
                    .format("Wrong value of the key encryption algorithm: " + keyEncryptionAlgorithm.toString()));
        }
        if (sharedSymmetricKey.length != keyLength) {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sharedSymmetricKey = sha.digest(sharedSymmetricKey);
            sharedSymmetricKey = Arrays.copyOf(sharedSymmetricKey, keyLength);
        }
        return new DirectEncrypter(sharedSymmetricKey);            
    }        
*/     
 /* 
        public enum AlgorithmFamily {
            NONE("none"),
            HMAC("HMAC"),
            RSA("RSA"),
            EC("EC"),
            ED("ED"),
            AES("AES"),
            PASSW("PASSW"),
            DIR("DIR");
        
        
        switch(keyEncryptionAlgorithm) {
        case RSA1_5:
        case RSA_OAEP:
        case RSA_OAEP_256: {
            break;
        }
        case ECDH_ES:
        case ECDH_ES_PLUS_A128KW:
        case ECDH_ES_PLUS_A192KW:
        case ECDH_ES_PLUS_A256KW: {
            break;
        }
        case A128KW:
        case A192KW:
        case A256KW:
        case A128GCMKW:
        case A192GCMKW:
        case A256GCMKW: {
            break;
        }
        case PBES2_HS256_PLUS_A128KW:
        case PBES2_HS384_PLUS_A192KW:
        }
        
        
        if (KeyEncryptionAlgorithm.RSA1_5.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.RSA_OAEP.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.RSA_OAEP_256.equals(keyEncryptionAlgorithm)) {
            return new RSAEncrypter(new RSAKey.Builder((RSAPublicKey) publicKey).build());
        } else if (KeyEncryptionAlgorithm.ECDH_ES.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.ECDH_ES_PLUS_A192KW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.ECDH_ES_PLUS_A256KW.equals(keyEncryptionAlgorithm)) {
            return new ECDHEncrypter(new ECKey.Builder(ecKey).build());
        } else if (KeyEncryptionAlgorithm.A128KW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.A256KW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.A192KW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.A128GCMKW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.A192GCMKW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.A256GCMKW.equals(keyEncryptionAlgorithm)) {
            if (sharedSymmetricKey == null) {
                throw new InvalidJweException("The shared symmetric key is null");
            }
            int keyLength;
            switch (keyEncryptionAlgorithm) {
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
                throw new InvalidJweException(String
                        .format("Wrong value of the key encryption algorithm: " + keyEncryptionAlgorithm.toString()));
            }
            if (sharedSymmetricKey.length != keyLength) {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                sharedSymmetricKey = sha.digest(sharedSymmetricKey);
                sharedSymmetricKey = Arrays.copyOf(sharedSymmetricKey, keyLength);
            }
            return new AESEncrypter(sharedSymmetricKey);
        } else if (KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW.equals(keyEncryptionAlgorithm) 
                || KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW.equals(keyEncryptionAlgorithm)) {
            return new PasswordBasedEncrypter(sharedSymmetricPassword, 16, 8192);
        } else if (KeyEncryptionAlgorithm.DIR.equals(keyEncryptionAlgorithm)) {
            return new DirectEncrypter(sharedSymmetricKey);
        } else {
            throw new InvalidJweException("The key encryption algorithm is not supported");
        }
*/        
    }

    public static Payload createPayload(Jwe jwe)
            throws ParseException, InvalidJwtException, UnsupportedEncodingException {
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

            JWEObject jweObject = new JWEObject(JWEHeader.parse(jwe.getHeader().toJsonObject().toString()),
                    createPayload(jwe));

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