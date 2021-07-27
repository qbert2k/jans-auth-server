/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2021, Janssen Project
 */
package io.jans.as.model.crypto.signature;

import java.security.spec.PKCS8EncodedKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PrivateKey;
import io.jans.as.model.util.StringUtils;

/**
 * 
 *
 * @author Sergey Manoylo
 * @version July 23, 2021
 */
public class EDDSAPrivateKey extends PrivateKey {
    
    private byte [] privateKeyData;

    /**
     * 
     * @param signatureAlgorithm
     * @param privateKeyData
     */
    public EDDSAPrivateKey(SignatureAlgorithm signatureAlgorithm, byte [] privateKeyData) {
    	setSignatureAlgorithm(signatureAlgorithm);
        this.privateKeyData = privateKeyData.clone();
    }

    /**
     * 
     * @param privateKeyDataStr
     */
    public EDDSAPrivateKey(String privateKeyDataStr) {
        this.privateKeyData =  privateKeyDataStr.getBytes().clone();
    }

    /**
     * 
     * @return
     */
    public PKCS8EncodedKeySpec getPrivateKeySpec() {
    	return new PKCS8EncodedKeySpec(privateKeyData);  
    }

    /**
     * 
     */
    @Override
    public JSONObject toJSONObject() throws JSONException {
/*    	
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(MODULUS, JSONObject.NULL);
        jsonObject.put(EXPONENT, JSONObject.NULL);
        jsonObject.put(D, Base64Util.base64urlencodeUnsignedBigInt(d));

        return jsonObject;
*/
    	return null;
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
    public EDDSAPrivateKey clone() {
    	EDDSAPrivateKey newObj = new EDDSAPrivateKey(getSignatureAlgorithm(), this.privateKeyData);
    	newObj.setKeyId(getKeyId());
    	return newObj;
    }
}
