/**
 * 
 */
package io.jans.as.model.crypto.signature;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * @author SMan
 *
 */
public enum EDEdwardsCurve {

    ED_25519("Ed25519", "Ed25519", "1.2.840.10045.3.1.7"),
    ED_448("Ed448", "Ed448", "1.3.132.0.10");
	
/*	
    ES256K			- "P-256K", "secp256k1", "1.3.132.0.10"
    EdDSA
    
	Ed25519
	Ed448    
    
	"crv"             EdDSA Variant
	Ed25519           Ed25519			1.3.6.1.4.1.11591.15.1
	Ed448             Ed448			1.3.101.113

	Ed25519 signature algorithm key pairs.
	public static final Curve Ed25519 = new Curve("Ed25519", "Ed25519", null);
	
	Ed448 signature algorithm key pairs.
	public static final Curve Ed448 = new Curve("Ed448", "Ed448", null);
	
*/		

    private final String name;
    private final String alias;
    private final String oid;

    private EDEdwardsCurve(String name, String alias, String oid) {
        this.name = name;
        this.alias = alias;
        this.oid = oid;
    }

    public String getName() {
        return name;
    }

    public String getAlias() {
        return alias;
    }

    public String getOid() {
        return oid;
    }

    /**
     * Returns the corresponding {@link ECEllipticCurve} for a parameter crv of the JWK endpoint.
     *
     * @param param The crv parameter.
     * @return The corresponding curve if found, otherwise <code>null</code>.
     */
    @JsonCreator
    public static EDEdwardsCurve fromString(String param) {
        if (param != null) {
            for (EDEdwardsCurve ec : EDEdwardsCurve.values()) {
                if (param.equals(ec.name) || param.equalsIgnoreCase(ec.name())) {
                    return ec;
                }
            }
        }
        return null;
    }

    /**
     * Returns a string representation of the object. In this case the parameter name.
     *
     * @return The string representation of the object.
     */
    @Override
    @JsonValue
    public String toString() {
        return name;
    }	

}
