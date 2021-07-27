/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2021, Janssen Project
 */
package io.jans.as.model.crypto.signature;

import java.security.spec.X509EncodedKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PublicKey;
import io.jans.as.model.util.StringUtils;

/**
 * 
 *
 * @author Sergey Manoylo
 * @version July 23, 2021
 */
public class EDDSAPublicKey extends PublicKey {
    
    private byte [] publicKeyData;

    /**
     * 
     * @param signatureAlgorithm
     * @param publicKeyData
     */
    public EDDSAPublicKey(SignatureAlgorithm signatureAlgorithm, byte [] publicKeyData) {
    	setSignatureAlgorithm(signatureAlgorithm);
        this.publicKeyData = publicKeyData.clone();        
    }

    /**
     * 
     * @param signatureAlgorithm
     * @param publicKeyDataStr
     */
    public EDDSAPublicKey(SignatureAlgorithm signatureAlgorithm, String publicKeyDataStr) {
        this(signatureAlgorithm, publicKeyDataStr.getBytes().clone());
    }

    /**
     * 
     * @return
     */
    public X509EncodedKeySpec getPublicKeySpec() {
    	return new X509EncodedKeySpec(publicKeyData);
    }

    /**
     * 
     */
    @Override
    public JSONObject toJSONObject() throws JSONException {
        JSONObject jsonObject = new JSONObject();
/*        
        jsonObject.put(MODULUS, JSONObject.NULL);
        jsonObject.put(EXPONENT, JSONObject.NULL);
        jsonObject.put(X, Base64Util.base64urlencodeUnsignedBigInt(x));
        jsonObject.put(Y, Base64Util.base64urlencodeUnsignedBigInt(y));
*/        
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
    	EDDSAPublicKey newObj = new EDDSAPublicKey(getSignatureAlgorithm(), this.publicKeyData);
    	newObj.setKeyId(getKeyId());
    	return newObj;
    }

}
