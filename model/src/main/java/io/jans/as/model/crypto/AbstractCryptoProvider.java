/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.crypto;

import com.google.common.collect.Lists;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.EllipticEdvardsCurve;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.JSONWebKeySet;
import io.jans.as.model.jwk.JWKParameter;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.util.Base64Util;
import io.jans.eleven.model.JwksRequestParam;
import io.jans.eleven.model.KeyRequestParam;
import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

/**
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public abstract class AbstractCryptoProvider {

    protected static final Logger LOG = Logger.getLogger(AbstractCryptoProvider.class);

    private int keyRegenerationIntervalInDays = -1;

    public JSONObject generateKey(Algorithm algorithm, Long expirationTime) throws Exception {
        return generateKey(algorithm, expirationTime, Use.SIGNATURE);
    }

    public abstract JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use) throws Exception;

    public abstract String sign(String signingInput, String keyId, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception;

    public abstract boolean verifySignature(String signingInput, String encodedSignature, String keyId, JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception;

    public abstract boolean deleteKey(String keyId) throws Exception;

    public abstract boolean containsKey(String keyId);

    public List<String> getKeys() {
        return Lists.newArrayList();
    }

    public abstract PrivateKey getPrivateKey(String keyId) throws Exception;

    public String getKeyId(JSONWebKeySet jsonWebKeySet, Algorithm algorithm, Use use) throws Exception {
        if (algorithm == null || AlgorithmFamily.HMAC.equals(algorithm.getFamily())) {
            return null;
        }
        for (JSONWebKey key : jsonWebKeySet.getKeys()) {
            if (algorithm == key.getAlg() && (use == null || use == key.getUse())) {
                return key.getKid();
            }
        }

        return null;
    }

    public JwksRequestParam getJwksRequestParam(JSONObject jwkJsonObject) throws JSONException {
        JwksRequestParam jwks = new JwksRequestParam();
        jwks.setKeyRequestParams(new ArrayList<>());

        KeyRequestParam key = new KeyRequestParam();
        key.setAlg(jwkJsonObject.getString(JWKParameter.ALGORITHM));
        key.setKid(jwkJsonObject.getString(JWKParameter.KEY_ID));
        key.setUse(jwkJsonObject.getString(JWKParameter.KEY_USE));
        key.setKty(jwkJsonObject.getString(JWKParameter.KEY_TYPE));

        key.setN(jwkJsonObject.optString(JWKParameter.MODULUS));
        key.setE(jwkJsonObject.optString(JWKParameter.EXPONENT));

        key.setCrv(jwkJsonObject.optString(JWKParameter.CURVE));
        key.setX(jwkJsonObject.optString(JWKParameter.X));
        key.setY(jwkJsonObject.optString(JWKParameter.Y));

        jwks.getKeyRequestParams().add(key);

        return jwks;
    }

    public static JSONObject generateJwks(AbstractCryptoProvider cryptoProvider, AppConfiguration configuration) {
        GregorianCalendar expirationTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        expirationTime.add(GregorianCalendar.HOUR, configuration.getKeyRegenerationInterval());
        expirationTime.add(GregorianCalendar.SECOND, configuration.getIdTokenLifetime());

        long expiration = expirationTime.getTimeInMillis();

        final List<String> allowedAlgs = configuration.getKeyAlgsAllowedForGeneration();
        JSONArray keys = new JSONArray();

        for (Algorithm alg : Algorithm.values()) {
            try {
                if (!allowedAlgs.isEmpty() && !allowedAlgs.contains(alg.getParamName())) {
                    LOG.debug("Key generation for " + alg + " is skipped because it's not allowed by keyAlgsAllowedForGeneration configuration property.");
                    continue;
                }
                keys.put(cryptoProvider.generateKey(alg, expiration, alg.getUse()));
            } catch (Exception ex) {
                LOG.error("Algorithm: " + alg + ex.getMessage(), ex);
            }
        }

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(JWKParameter.JSON_WEB_KEY_SET, keys);

        return jsonObject;
    }

    public PublicKey getPublicKey(String alias, JSONObject jwks, Algorithm requestedAlgorithm) throws Exception {
        JSONArray webKeys = jwks.getJSONArray(JWKParameter.JSON_WEB_KEY_SET);
        if (alias == null) {
            if (webKeys.length() == 1) {
                JSONObject key = webKeys.getJSONObject(0);
                return processKey(requestedAlgorithm, alias, key);
            } else {
                return null;
            }
        }
        for (int i = 0; i < webKeys.length(); i++) {
            JSONObject key = webKeys.getJSONObject(i);
            if (alias.equals(key.getString(JWKParameter.KEY_ID))) {
                PublicKey publicKey = processKey(requestedAlgorithm, alias, key);
                if (publicKey != null) {
                    return publicKey;
                }
            }
        }

        return null;
    }

    private PublicKey processKey(Algorithm requestedAlgorithm, String alias, JSONObject key) throws Exception {
        PublicKey publicKey = null;
        AlgorithmFamily family = null;

        if (key.has(JWKParameter.ALGORITHM)) {
            Algorithm algorithm = Algorithm.fromString(key.optString(JWKParameter.ALGORITHM));

            if (requestedAlgorithm != null && !requestedAlgorithm.equals(algorithm)) {
                LOG.trace("kid matched but algorithm does not match. kid algorithm:" + algorithm + ", requestedAlgorithm:" + requestedAlgorithm + ", kid:" + alias);
                return null;
            }
            family = algorithm.getFamily();
        } else if (key.has(JWKParameter.KEY_TYPE)) {
            family = AlgorithmFamily.fromString(key.getString(JWKParameter.KEY_TYPE));
        }
        
        switch(family) {
        case RSA: {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                    new BigInteger(1, Base64Util.base64urldecode(key.getString(JWKParameter.MODULUS))),
                    new BigInteger(1, Base64Util.base64urldecode(key.getString(JWKParameter.EXPONENT))));
            publicKey = keyFactory.generatePublic(pubKeySpec);
            break;
        }
        case EC: {
            EllipticEdvardsCurve curve = EllipticEdvardsCurve.fromString(key.optString(JWKParameter.CURVE));
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(AlgorithmFamily.EC.toString());
            parameters.init(new ECGenParameterSpec(curve.getAlias()));
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            publicKey = KeyFactory.getInstance(AlgorithmFamily.EC.toString()).generatePublic(new ECPublicKeySpec(
                    new ECPoint(
                            new BigInteger(1, Base64Util.base64urldecode(key.getString(JWKParameter.X))),
                            new BigInteger(1, Base64Util.base64urldecode(key.getString(JWKParameter.Y)))
                    ), ecParameters));
            break;
        }
        case ED: {
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64Util.base64urldecode(key.getString(JWKParameter.X)));
            publicKey = KeyFactory.getInstance(key.optString(JWKParameter.ALGORITHM)).generatePublic(publicKeySpec);
            break;
        }
        default: {
            throw new Exception("Wrong value AlgorithmFamily: " + family.toString());            
        }
        }

        if (key.has(JWKParameter.EXPIRATION_TIME)) {
            checkKeyExpiration(alias, key.getLong(JWKParameter.EXPIRATION_TIME));
        }

        return publicKey;
    }

    protected void checkKeyExpiration(String alias, Long expirationTime) {
        try {
            Date expirationDate = new Date(expirationTime);
            SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            Date today = new Date();
            long expiresInDays = (expirationTime - today.getTime()) / (24 * 60 * 60 * 1000);
            if (expiresInDays == 0) {
                LOG.warn("\nWARNING! Key will expire soon, alias: " + alias
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
                return;
            }
            if (expiresInDays < 0) {
                LOG.warn("\nWARNING! Expired Key is used, alias: " + alias
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
                return;
            }

            // re-generation interval is unknown, therefore we default to 30 days period warning
            if (keyRegenerationIntervalInDays <= 0 && expiresInDays < 30) {
                LOG.warn("\nWARNING! Key with alias: " + alias
                        + "\n\tExpires In: " + expiresInDays + " days"
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
                return;
            }

            if (expiresInDays < keyRegenerationIntervalInDays) {
                LOG.warn("\nWARNING! Key with alias: " + alias
                        + "\n\tExpires In: " + expiresInDays + " days"
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tKey Regeneration In: " + keyRegenerationIntervalInDays + " days"
                        + "\n\tToday's Date: " + ft.format(today));
            }
        } catch (Exception e) {
            LOG.error("Failed to check key expiration.", e);
        }
    }

    public int getKeyRegenerationIntervalInDays() {
        return keyRegenerationIntervalInDays;
    }

    public void setKeyRegenerationIntervalInDays(int keyRegenerationIntervalInDays) {
        this.keyRegenerationIntervalInDays = keyRegenerationIntervalInDays;
    }
}