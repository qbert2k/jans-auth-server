/**
 * 
 */
package io.jans.as.model.crypto.signature;

import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PrivateKey;
import io.jans.as.model.util.StringUtils;

/**
 * @author SMan
 *
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
        this.privateKeyData = privateKeyData;
    }

    /**
     * 
     * @param privateKeyDataStr
     */
    public EDDSAPrivateKey(String privateKeyDataStr) {
        this.privateKeyData =  privateKeyDataStr.getBytes();
    }

    /**
     * 
     * @return
     */
    public byte [] getPrivateKeyData() {
        return this.privateKeyData;
    }

    /**
     * 
     * @param privateKeyData
     */
    public void setPrivateKeyData(byte [] privateKeyData) {
        this.privateKeyData = privateKeyData;
    }

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
    
}
