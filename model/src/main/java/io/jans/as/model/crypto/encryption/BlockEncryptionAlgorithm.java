/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.crypto.encryption;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * @author Javier Rojas Blum Date: 12.03.2012
 */
public enum BlockEncryptionAlgorithm {

    A128CBC_PLUS_HS256("A128CBC+HS256", "CBC", "AES/CBC/PKCS5Padding", "SHA-256", "HMACSHA256", 256, 128, 256),
    A256CBC_PLUS_HS512("A256CBC+HS512", "CBC", "AES/CBC/PKCS5Padding", "SHA-512", "HMACSHA512", 512, 128, 512),
    A128CBC_HS256("A128CBC-HS256", "CBC", "AES/CBC/PKCS5Padding", "SHA-256", "HMACSHA256", 256, 128, 256),
    A192CBC_HS384("A192CBC-HS384", "CBC", "AES/CBC/PKCS5Padding", "SHA-384", "HMACSHA384", 384, 128, 284),    
    A256CBC_HS512("A256CBC-HS512", "CBC", "AES/CBC/PKCS5Padding", "SHA-512", "HMACSHA512", 512, 128, 512),
    A128GCM("A128GCM", "GCM", "AES/GCM/NoPadding", 128, 128),
    A192GCM("A192GCM", "GCM", "AES/GCM/NoPadding", 192, 128),    
    A256GCM("A256GCM", "GCM", "AES/GCM/NoPadding", 256, 128);
	
/*
	A128CBC-HS256,
	A192CBC-HS384,
	A256CBC-HS512,
	A128CBC+HS256 (deprecated),
	A256CBC+HS512 (deprecated)
	
	A256CBC+HS512	
	
 */
	
/*
    private BlockEncryptionAlgorithm(String name, String family, String algorithm, String messageDiggestAlgorithm,
                                     String integrityValueAlgorithm, int cmkLength, int initVectorLength, int cekLength) 	
*/
/*	
	A128CBC-HS256,
	A192CBC-HS384,
	A256CBC-HS512,
	A128GCM,
	A192GCM,
	A256GCM	
*/	
/*	
	assertEquals(8, DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.size());
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
	assertTrue(DirectDecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

	assertEquals(8, DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.size());
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256));
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192CBC_HS384));
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512));
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128GCM));
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A192GCM));
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256GCM));
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
	assertTrue(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
*/		

    private final String name;
    private final String family;
    private final String algorithm;
    private final String messageDiggestAlgorithm;
    private final String integrityValueAlgorithm;
    private final int cmkLength;
    private final int initVectorLength;
    private final Integer cekLength;

    private BlockEncryptionAlgorithm(String name, String family, String algorithm, int cmkLength, int initVectorLength) {
        this.name = name;
        this.family = family;
        this.algorithm = algorithm;
        this.messageDiggestAlgorithm = null;
        this.integrityValueAlgorithm = null;
        this.cmkLength = cmkLength;
        this.initVectorLength=initVectorLength;
        this.cekLength = null;
    }

    private BlockEncryptionAlgorithm(String name, String family, String algorithm, String messageDiggestAlgorithm,
                                     String integrityValueAlgorithm, int cmkLength, int initVectorLength, int cekLength) {
        this.name = name;
        this.family = family;
        this.algorithm = algorithm;
        this.messageDiggestAlgorithm = messageDiggestAlgorithm;
        this.integrityValueAlgorithm = integrityValueAlgorithm;
        this.cmkLength = cmkLength;
        this.initVectorLength=initVectorLength;
        this.cekLength = cekLength;
    }

    public String getName() {
        return name;
    }

    public String getFamily() {
        return family;
    }

    public String getMessageDiggestAlgorithm() {
        return messageDiggestAlgorithm;
    }

    public String getIntegrityValueAlgorithm() {
        return integrityValueAlgorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getCmkLength() {
        return cmkLength;
    }

    public int getInitVectorLength() {
        return initVectorLength;
    }

    public Integer getCekLength() {
        return cekLength;
    }

    @JsonCreator
    public static BlockEncryptionAlgorithm fromName(String name) {
        if (name != null) {
            for (BlockEncryptionAlgorithm a : BlockEncryptionAlgorithm.values()) {
                if (name.equals(a.name)) {
                    return a;
                }
            }
        }
        return null;
    }

    @Override
    @JsonValue
    public String toString() {
        return name;
    }
}