/**
 * 
 */
package io.jans.as.model.crypto.signature;

import static io.jans.as.model.jwk.JWKParameter.EXPONENT;
import static io.jans.as.model.jwk.JWKParameter.MODULUS;
import static io.jans.as.model.jwk.JWKParameter.X;
import static io.jans.as.model.jwk.JWKParameter.Y;

import java.math.BigInteger;

import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PublicKey;
import io.jans.as.model.util.Base64Util;
import io.jans.as.model.util.StringUtils;

/**
 * @author SMan
 *
 */
public class EDDSAPublicKey  extends PublicKey {

    private static final String EDDSA_ALGORITHM = "ED";
    private static final String USE = "sig";

    private SignatureAlgorithm signatureAlgorithm;
    private BigInteger x;
    private BigInteger y;

    public EDDSAPublicKey(SignatureAlgorithm signatureAlgorithm, BigInteger x, BigInteger y) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.x = x;
        this.y = y;
    }

    public EDDSAPublicKey(SignatureAlgorithm signatureAlgorithm, String x, String y) {
        this(signatureAlgorithm,
                new BigInteger(1, Base64Util.base64urldecode(x)),
                new BigInteger(1, Base64Util.base64urldecode(y)));
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public BigInteger getX() {
        return x;
    }

    public void setX(BigInteger x) {
        this.x = x;
    }

    public BigInteger getY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }

    @Override
    public JSONObject toJSONObject() throws JSONException {
        JSONObject jsonObject = new JSONObject();

        jsonObject.put(MODULUS, JSONObject.NULL);
        jsonObject.put(EXPONENT, JSONObject.NULL);
        jsonObject.put(X, Base64Util.base64urlencodeUnsignedBigInt(x));
        jsonObject.put(Y, Base64Util.base64urlencodeUnsignedBigInt(y));

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
