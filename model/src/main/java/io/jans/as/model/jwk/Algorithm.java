/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.jwk;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.nimbusds.jose.JWSAlgorithm;

import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.EllipticEdvardsCurve;
import io.jans.as.model.util.StringUtils;

/**
 * Identifies the cryptographic algorithm used with the key.
 *
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public enum Algorithm {

    // Signature
    RS256("RS256", Use.SIGNATURE, AlgorithmFamily.RSA),
    RS384("RS384", Use.SIGNATURE, AlgorithmFamily.RSA),
    RS512("RS512", Use.SIGNATURE, AlgorithmFamily.RSA),
    
    ES256("ES256", Use.SIGNATURE, AlgorithmFamily.EC),
    ES256K("ES256K", Use.SIGNATURE, AlgorithmFamily.EC),
    ES384("ES384", Use.SIGNATURE, AlgorithmFamily.EC),
    ES512("ES512", Use.SIGNATURE, AlgorithmFamily.EC),
    
    PS256("PS256", Use.SIGNATURE, AlgorithmFamily.RSA),
    PS384("PS384", Use.SIGNATURE, AlgorithmFamily.RSA),
    PS512("PS512", Use.SIGNATURE, AlgorithmFamily.RSA),

    // Encryption
    RSA1_5("RSA1_5", Use.ENCRYPTION, AlgorithmFamily.RSA),
    RSA_OAEP("RSA-OAEP", Use.ENCRYPTION, AlgorithmFamily.RSA),
    RSA_OAEP_256("RSA-OAEP-256", Use.ENCRYPTION, AlgorithmFamily.RSA),
    
    ECDH_ES("ECDH-ES", Use.ENCRYPTION, AlgorithmFamily.EC),
    ECDH_ES_PLUS_A128KW("ECDH-ES+A128KW", Use.ENCRYPTION, AlgorithmFamily.EC),
    ECDH_ES_PLUS_A192KW("ECDH-ES+A192KW", Use.ENCRYPTION, AlgorithmFamily.EC),
    ECDH_ES_PLUS_A256KW("ECDH-ES+A256KW", Use.ENCRYPTION, AlgorithmFamily.EC),
    
    ED25519("Ed25519", Use.SIGNATURE, AlgorithmFamily.ED),
    ED448("Ed448", Use.SIGNATURE, AlgorithmFamily.ED);

/*
 
    A128CBC_PLUS_HS256("A128CBC+HS256", "CBC", "AES/CBC/PKCS5Padding", "SHA-256", "HMACSHA256", 256, 128, 256),
    A256CBC_PLUS_HS512("A256CBC+HS512", "CBC", "AES/CBC/PKCS5Padding", "SHA-512", "HMACSHA512", 512, 128, 512),
    A128CBC_HS256("A128CBC-HS256", "CBC", "AES/CBC/PKCS5Padding", "SHA-256", "HMACSHA256", 256, 128, 256),
    A192CBC_HS384("A192CBC-HS384", "CBC", "AES/CBC/PKCS5Padding", "SHA-384", "HMACSHA384", 384, 128, 284),
    A256CBC_HS512("A256CBC-HS512", "CBC", "AES/CBC/PKCS5Padding", "SHA-512", "HMACSHA512", 512, 128, 512),
    A128GCM("A128GCM", "GCM", "AES/GCM/NoPadding", 128, 128),
    A192GCM("A192GCM", "GCM", "AES/GCM/NoPadding", 192, 128),
    A256GCM("A256GCM", "GCM", "AES/GCM/NoPadding", 256, 128);
    
 */
/*

    RSA1_5("RSA1_5", "RSA", "RSA/ECB/PKCS1Padding"),
    RSA_OAEP("RSA-OAEP", "RSA", "RSA/ECB/OAEPWithSHA1AndMGF1Padding"),
    RSA_OAEP_256("RSA-OAEP-256"),

    ECDH_ES("ECDH-ES"),
    ECDH_ES_PLUS_A128KW("ECDH-ES+A128KW"),
    ECDH_ES_PLUS_A192KW("ECDH-ES+A192KW"),
    ECDH_ES_PLUS_A256KW("ECDH-ES+A256KW"),

    A128KW("A128KW"),
    A192KW("A192KW"),
    A256KW("A256KW"),
    
    A128GCMKW("A128GCMKW"),
    A192GCMKW("A192GCMKW"),
    A256GCMKW("A256GCMKW"),

    PBES2_HS256_PLUS_A128KW("PBES2-HS256+A128KW"),
    PBES2_HS384_PLUS_A192KW("PBES2-HS384+A192KW"),
    PBES2_HS512_PLUS_A256KW("PBES2-HS512+A256KW"),

    DIR("dir");

 */
    
/*

   NONE("none"), HS256("HS256", AlgorithmFamily.HMAC, "HMACSHA256", JWSAlgorithm.HS256),
    HS384("HS384", AlgorithmFamily.HMAC, "HMACSHA384", JWSAlgorithm.HS384),
    HS512("HS512", AlgorithmFamily.HMAC, "HMACSHA512", JWSAlgorithm.HS512),
    
    RS256("RS256", AlgorithmFamily.RSA, "SHA256WITHRSA", JWSAlgorithm.RS256),
    RS384("RS384", AlgorithmFamily.RSA, "SHA384WITHRSA", JWSAlgorithm.RS384),
    RS512("RS512", AlgorithmFamily.RSA, "SHA512WITHRSA", JWSAlgorithm.RS512),
    
    ES256("ES256", AlgorithmFamily.EC, "SHA256WITHECDSA", EllipticEdvardsCurve.P_256, JWSAlgorithm.ES256),
    ES256K("ES256K", AlgorithmFamily.EC, "SHA256WITHECDSA", EllipticEdvardsCurve.P_256K, JWSAlgorithm.ES256K),
    ES384("ES384", AlgorithmFamily.EC, "SHA384WITHECDSA", EllipticEdvardsCurve.P_384, JWSAlgorithm.ES384),
    ES512("ES512", AlgorithmFamily.EC, "SHA512WITHECDSA", EllipticEdvardsCurve.P_521, JWSAlgorithm.ES512),
    
    PS256("PS256", AlgorithmFamily.RSA, "SHA256withRSAandMGF1", JWSAlgorithm.PS256),
    PS384("PS384", AlgorithmFamily.RSA, "SHA384withRSAandMGF1", JWSAlgorithm.PS384),
    PS512("PS512", AlgorithmFamily.RSA, "SHA512withRSAandMGF1", JWSAlgorithm.PS512),
    
    ED25519("Ed25519", AlgorithmFamily.ED, "Ed25519", JWSAlgorithm.EdDSA),
    ED448("Ed448", AlgorithmFamily.ED, "Ed448", JWSAlgorithm.EdDSA),
    EDDSA("EdDSA", AlgorithmFamily.ED, "Ed25519", JWSAlgorithm.EdDSA);
     
 */
    
    
/*    
---------------------------------------------    
com.nimbusds.jose
    Class JWSAlgorithm    
    
    HS256
    HS384
    HS512
    RS256
    RS384
    RS512
    ES256
    ES384
    ES512
    PS256
    PS384
    PS512
    EdDSA
    ES256K (non-standard)
---------------------------------------------
com.nimbusds.jose
    Class JWEAlgorithm
    
    RSA-OAEP-256
    RSA-OAEP (deprecated)
    RSA1_5 (deprecated)
    A128KW
    A192KW
    A256KW
    dir
    ECDH-ES
    ESDH-ES+A128KW
    ESDH-ES+A192KW
    ESDH-ES+A256KW
    PBES2-HS256+A128KW
    PBES2-HS256+A192KW
    PBES2-HS256+A256KW    

---------------------------------------------    
*/

    private final String paramName;
    private final Use use;
    private final AlgorithmFamily family;

    Algorithm(String paramName, Use use, AlgorithmFamily family) {
        this.paramName = paramName;
        this.use = use;
        this.family = family;
    }

    public String getParamName() {
        return paramName;
    }

    public Use getUse() {
        return use;
    }

    public AlgorithmFamily getFamily() {
        return family;
    }

    /**
     * Returns the corresponding {@link Algorithm} for a parameter.
     *
     * @param param The use parameter.
     * @return The corresponding algorithm if found, otherwise <code>null</code>.
     */
    @JsonCreator
    public static Algorithm fromString(String param) {
        if (param != null) {
            for (Algorithm algorithm : Algorithm.values()) {
                if (param.equals(algorithm.paramName)) {
                    return algorithm;
                }
            }
        }
        return null;
    }

    public static List<Algorithm> fromString(String[] params, Use use) {
        List<Algorithm> algorithms = new ArrayList<Algorithm>();

        for (String param : params) {
            Algorithm algorithm = Algorithm.fromString(param);
            if (algorithm != null && algorithm.use == use) {
                algorithms.add(algorithm);
            } else if (StringUtils.equals("RSA_OAEP", param)) {
                algorithms.add(RSA_OAEP);
            }
        }

        return algorithms;
    }

    /**
     * Returns a string representation of the object. In this case the parameter
     * name.
     *
     * @return The string representation of the object.
     */
    @Override
    @JsonValue
    public String toString() {
        return paramName;
    }
}