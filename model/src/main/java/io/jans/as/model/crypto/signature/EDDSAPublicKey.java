/**
 * 
 */
package io.jans.as.model.crypto.signature;

import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PublicKey;
import io.jans.as.model.util.StringUtils;

/**
 * @author SMan
 *
 */
public class EDDSAPublicKey  extends PublicKey {

    private static final String EDDSA_ALGORITHM = "ED";
    private static final String USE = "sig";

    private SignatureAlgorithm signatureAlgorithm;
    
    private byte [] publicKeyData;
    private byte [] privateKeyData;

    public EDDSAPublicKey(SignatureAlgorithm signatureAlgorithm, byte [] publicKeyData, byte [] privateKeyData) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyData = publicKeyData;        
        this.privateKeyData = privateKeyData;
    }

    public EDDSAPublicKey(SignatureAlgorithm signatureAlgorithm, String publicKeyDataStr, String privateKeyDataStr) {
        this(signatureAlgorithm, publicKeyDataStr.getBytes(), privateKeyDataStr.getBytes());
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte [] getPublicKeyData() {
        return publicKeyData;
    }

    public void setPublicKeyData(byte [] publicKeyData) {
        this.publicKeyData = publicKeyData;
    }

    public byte [] getPrivateKeyData() {
        return privateKeyData;
    }

    public void setPrivateKeyData(byte [] privateKeyData) {
        this.privateKeyData = privateKeyData;
    }

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
