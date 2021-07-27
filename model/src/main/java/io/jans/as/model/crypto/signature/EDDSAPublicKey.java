/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2021, Janssen Project
 */
package io.jans.as.model.crypto.signature;

import static io.jans.as.model.jwk.JWKParameter.EXPONENT;
import static io.jans.as.model.jwk.JWKParameter.MODULUS;
import static io.jans.as.model.jwk.JWKParameter.X;

import java.security.spec.X509EncodedKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PublicKey;
import io.jans.as.model.util.Base64Util;
import io.jans.as.model.util.StringUtils;

/**
 * 
 *
 * @author Sergey Manoylo
 * @version July 23, 2021
 */
public class EDDSAPublicKey extends PublicKey {
	
    private byte [] xEncoded;	

    /**
     * 
     * @param signatureAlgorithm
     * @param publicKeyData
     */
    public EDDSAPublicKey(SignatureAlgorithm signatureAlgorithm, byte [] xEncoded) {
    	setSignatureAlgorithm(signatureAlgorithm);
        this.xEncoded = xEncoded.clone();        
    }

    /**
     * 
     * @return
     */
    public X509EncodedKeySpec getPublicKeySpec() {
    	return new X509EncodedKeySpec(this.xEncoded);
    }

    /**
     * 
     */
    @Override
    public JSONObject toJSONObject() throws JSONException {
    	JSONObject jsonObject = new JSONObject();
        jsonObject.put(MODULUS, JSONObject.NULL);
        jsonObject.put(EXPONENT, JSONObject.NULL);
        jsonObject.put(X, Base64Util.base64urlencode(this.xEncoded));
    	return jsonObject;    	
    }

    /**
     * 
     */
    @Override
    public String toString() {
        try {
            return toJSONObject().toString(4);
        } catch (JSONException e) {
            return StringUtils.EMPTY_STRING;
        } catch (Exception e) {
            return StringUtils.EMPTY_STRING;
        }
    }	
    
    /**
     * 
     */
    @Override
    public EDDSAPublicKey clone() {
    	EDDSAPublicKey newObj = new EDDSAPublicKey(getSignatureAlgorithm(), this.xEncoded);
    	newObj.setKeyId(getKeyId());
    	return newObj;
    }

}
