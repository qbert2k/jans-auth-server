/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.jwk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsonorg.JsonOrgModule;

import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;

/**
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public class JSONWebKeySet {

    @JsonIgnore
    private static final Logger LOG = LoggerFactory.getLogger(JSONWebKeySet.class);

    private List<JSONWebKey> keys;

    public JSONWebKeySet() {
        keys = new ArrayList<JSONWebKey>();
    }

    public List<JSONWebKey> getKeys() {
        return keys;
    }

    public void setKeys(List<JSONWebKey> keys) {
        this.keys = keys;
    }

    public JSONWebKey getKey(String keyId) {
        for (JSONWebKey jsonWebKey : keys) {
            if (jsonWebKey.getKid().equals(keyId)) {
                return jsonWebKey;
            }
        }
        return null;
    }

    @Deprecated
    public List<JSONWebKey> getKeys(SignatureAlgorithm signatureAlgorithm) {
        List<JSONWebKey> jsonWebKeys = new ArrayList<JSONWebKey>();
        AlgorithmFamily algorithmFamily = signatureAlgorithm.getFamily();
        if (AlgorithmFamily.RSA.equals(algorithmFamily) || AlgorithmFamily.EC.equals(algorithmFamily)
                || AlgorithmFamily.ED.equals(algorithmFamily)) {
            for (JSONWebKey jsonWebKey : keys) {
                if (jsonWebKey.getAlg().equals(signatureAlgorithm.getAlg())) {
                    jsonWebKeys.add(jsonWebKey);
                }
            }
        }
        Collections.sort(jsonWebKeys);
        return jsonWebKeys;
    }

    public JSONObject toJSONObject() throws JSONException {
        JSONObject jsonObj = new JSONObject();
        JSONArray jKeys = new JSONArray();

        for (JSONWebKey key : getKeys()) {
            JSONObject jsonKeyValue = key.toJSONObject();

            jKeys.put(jsonKeyValue);
        }

        jsonObj.put(JWKParameter.JSON_WEB_KEY_SET, jKeys);
        return jsonObj;
    }

    @Override
    public String toString() {
        try {
            JSONObject jwks = toJSONObject();
            return toPrettyJson(jwks).replace("\\/", "/");
        } catch (JSONException e) {
            LOG.error(e.getMessage(), e);
            return "";
        } catch (JsonProcessingException e) {
            LOG.error(e.getMessage(), e);
            return "";
        }
    }

    private String toPrettyJson(JSONObject jsonObject) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JsonOrgModule());
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
    }

    public static JSONWebKeySet fromJSONObject(JSONObject jwksJSONObject) throws JSONException {
        JSONWebKeySet jwks = new JSONWebKeySet();

        JSONArray jwksJsonArray = jwksJSONObject.getJSONArray(JWKParameter.JSON_WEB_KEY_SET);
        for (int i = 0; i < jwksJsonArray.length(); i++) {
            JSONObject jwkJsonObject = jwksJsonArray.getJSONObject(i);

            JSONWebKey jwk = JSONWebKey.fromJSONObject(jwkJsonObject);
            jwks.getKeys().add(jwk);
        }

        return jwks;
    }
}