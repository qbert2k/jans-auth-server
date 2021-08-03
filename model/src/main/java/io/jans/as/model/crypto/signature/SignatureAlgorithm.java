/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.crypto.signature;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.nimbusds.jose.JWSAlgorithm;

import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.jwt.JwtType;

/**
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public enum SignatureAlgorithm {

    NONE("none"),
    
    HS256("HS256", AlgorithmFamily.HMAC, "HMACSHA256", JWSAlgorithm.HS256),
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

    private final String name;
    private final AlgorithmFamily family;
    private final String algorithm;
    private final EllipticEdvardsCurve curve;
    private final JwtType jwtType;
    private final JWSAlgorithm jwsAlgorithm;
    private final Algorithm alg;

    SignatureAlgorithm(String name, AlgorithmFamily family, String algorithm, EllipticEdvardsCurve curve,
            JWSAlgorithm jwsAlgorithm) {
        this.name = name;
        this.family = family;
        this.algorithm = algorithm;
        this.curve = curve;
        this.jwtType = JwtType.JWT;
        this.jwsAlgorithm = jwsAlgorithm;
        this.alg = Algorithm.fromString(name);
    }

    SignatureAlgorithm(String name, AlgorithmFamily family, String algorithm, JWSAlgorithm jwsAlgorithm) {
        this(name, family, algorithm, null, jwsAlgorithm);
    }

    SignatureAlgorithm(String name) {
        this(name, null, null, null, null);
    }

    public Algorithm getAlg() {
        return alg;
    }

    public String getName() {
        return name;
    }

    public AlgorithmFamily getFamily() {
        return family;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public EllipticEdvardsCurve getCurve() {
        return curve;
    }

    public JwtType getJwtType() {
        return jwtType;
    }

    public static List<SignatureAlgorithm> fromString(String[] params) {
        List<SignatureAlgorithm> signatureAlgorithms = new ArrayList<SignatureAlgorithm>();

        for (String param : params) {
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(param);
            if (signatureAlgorithm != null) {
                signatureAlgorithms.add(signatureAlgorithm);
            }
        }

        return signatureAlgorithms;
    }

    /**
     * Returns the corresponding {@link SignatureAlgorithm} for a parameter alg of
     * the JWK endpoint.
     *
     * @param param The alg parameter.
     * @return The corresponding alg if found, otherwise <code>null</code>.
     */
    @JsonCreator
    public static SignatureAlgorithm fromString(String param) {
        if (param != null) {
            for (SignatureAlgorithm sa : SignatureAlgorithm.values()) {
                if (param.equals(sa.name)) {
                    return sa;
                }
            }
        }
        return null;
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
        return name;
    }

    /**
     * 
     * @return
     */
    public JWSAlgorithm getJwsAlgorithm() {
        return jwsAlgorithm;
    }
}

