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
import io.jans.as.model.jwt.JwtType;

/**
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public enum SignatureAlgorithm {

    NONE("none", AlgorithmFamily.NONE, null, null),

    HS256(SignatureAlgorithm.defHS256, AlgorithmFamily.HMAC, SignatureAlgorithm.defHMACSHA256, JWSAlgorithm.HS256),
    HS384(SignatureAlgorithm.defHS384, AlgorithmFamily.HMAC, SignatureAlgorithm.defHMACSHA384, JWSAlgorithm.HS384),
    HS512(SignatureAlgorithm.defHS512, AlgorithmFamily.HMAC, SignatureAlgorithm.defHMACSHA512, JWSAlgorithm.HS512),

    RS256(SignatureAlgorithm.defRS256, AlgorithmFamily.RSA, SignatureAlgorithm.defSHA256WITHRSA, JWSAlgorithm.RS256),
    RS384(SignatureAlgorithm.defRS384, AlgorithmFamily.RSA, SignatureAlgorithm.defSHA384WITHRSA, JWSAlgorithm.RS384),
    RS512(SignatureAlgorithm.defRS512, AlgorithmFamily.RSA, SignatureAlgorithm.defSHA512WITHRSA, JWSAlgorithm.RS512),

    ES256(SignatureAlgorithm.defES256, AlgorithmFamily.EC, SignatureAlgorithm.defSHA256WITHECDSA, EllipticEdvardsCurve.P_256, JWSAlgorithm.ES256),
    ES256K(SignatureAlgorithm.defES256K, AlgorithmFamily.EC, SignatureAlgorithm.defSHA256WITHECDSA, EllipticEdvardsCurve.P_256K, JWSAlgorithm.ES256K),
    ES384(SignatureAlgorithm.defES384, AlgorithmFamily.EC, SignatureAlgorithm.defSHA384WITHECDSA, EllipticEdvardsCurve.P_384, JWSAlgorithm.ES384),
    ES512(SignatureAlgorithm.defES512, AlgorithmFamily.EC, SignatureAlgorithm.defSHA512WITHECDSA, EllipticEdvardsCurve.P_521, JWSAlgorithm.ES512),

    PS256(SignatureAlgorithm.defPS256, AlgorithmFamily.RSA, SignatureAlgorithm.defSHA256WITHRSAANDMGF1, JWSAlgorithm.PS256),
    PS384(SignatureAlgorithm.defPS384, AlgorithmFamily.RSA, SignatureAlgorithm.defSHA384WITHRSAANDMGF1, JWSAlgorithm.PS384),
    PS512(SignatureAlgorithm.defPS512, AlgorithmFamily.RSA, SignatureAlgorithm.defSHA512WITHRSAANDMGF1, JWSAlgorithm.PS512),

    ED25519(SignatureAlgorithm.defED25519, AlgorithmFamily.ED, SignatureAlgorithm.defED25519, EllipticEdvardsCurve.ED_25519, JWSAlgorithm.EdDSA),
    ED448(SignatureAlgorithm.defED448, AlgorithmFamily.ED, SignatureAlgorithm.defED448, EllipticEdvardsCurve.ED_448, JWSAlgorithm.EdDSA),
    EDDSA(SignatureAlgorithm.defEDDDSA, AlgorithmFamily.ED, SignatureAlgorithm.defED25519, EllipticEdvardsCurve.ED_25519, JWSAlgorithm.EdDSA);

    public static final String defHS256 = "HS256";
    public static final String defHS384 = "HS384";
    public static final String defHS512 = "HS512";

    public static final String defRS256 = "RS256";
    public static final String defRS384 = "RS384";
    public static final String defRS512 = "RS512";

    public static final String defES256 = "ES256";
    public static final String defES256K = "ES256K";
    public static final String defES384 = "ES384";
    public static final String defES512 = "ES512";

    public static final String defPS256 = "PS256";
    public static final String defPS384 = "PS384";
    public static final String defPS512 = "PS512";

    public static final String defED25519 = "Ed25519";
    public static final String defED448 = "Ed448";
    public static final String defEDDDSA = "EdDSA";

    public static final String defHMACSHA256 = "HMACSHA256";
    public static final String defHMACSHA384 = "HMACSHA384";
    public static final String defHMACSHA512 = "HMACSHA512";

    public static final String defSHA256WITHRSA = "SHA256WITHRSA";
    public static final String defSHA384WITHRSA = "SHA384WITHRSA";
    public static final String defSHA512WITHRSA = "SHA512WITHRSA";

    public static final String defSHA256WITHECDSA = "SHA256WITHECDSA";
    public static final String defSHA384WITHECDSA = "SHA384WITHECDSA";
    public static final String defSHA512WITHECDSA = "SHA512WITHECDSA";

    public static final String defSHA256WITHRSAANDMGF1 = "SHA256withRSAandMGF1";
    public static final String defSHA384WITHRSAANDMGF1 = "SHA384withRSAandMGF1";
    public static final String defSHA512WITHRSAANDMGF1 = "SHA512withRSAandMGF1";

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
