/**
 * 
 */
package io.jans.as.model.crypto.signature;

import static io.jans.as.model.jwk.JWKParameter.D;
import static io.jans.as.model.jwk.JWKParameter.EXPONENT;
import static io.jans.as.model.jwk.JWKParameter.MODULUS;

import java.math.BigInteger;

import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PrivateKey;
import io.jans.as.model.util.Base64Util;
import io.jans.as.model.util.StringUtils;

/**
 * @author SMan
 *
 */
public class EDDSAPrivateKey extends PrivateKey {
    
    private byte [] privateKeyData;

    public EDDSAPrivateKey(byte [] privateKeyData) {
        this.privateKeyData = privateKeyData;
    }

    public EDDSAPrivateKey(String privateKeyDataStr) {
        this.privateKeyData =  privateKeyDataStr.getBytes();
    }

    public byte [] getPrivateKeyData() {
        return privateKeyData;
    }

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
