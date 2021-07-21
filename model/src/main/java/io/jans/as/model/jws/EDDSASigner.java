/**
 * 
 */
package io.jans.as.model.jws;

import java.security.SignatureException;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;

import io.jans.as.model.crypto.Certificate;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;


/**
 * @author SMan
 *
 */
public class EDDSASigner extends AbstractJwsSigner {
	
    private BCEdDSAPrivateKey eddsaPrivateKey;
    private BCEdDSAPublicKey eddsaPublicKey;
    
    public EDDSASigner(SignatureAlgorithm signatureAlgorithm, BCEdDSAPrivateKey eddsaPrivateKey) {
        super(signatureAlgorithm);
        this.eddsaPrivateKey = eddsaPrivateKey;
    }
    
    public EDDSASigner(SignatureAlgorithm signatureAlgorithm, BCEdDSAPublicKey eddsaPublicKey) {
        super(signatureAlgorithm);
        this.eddsaPublicKey = eddsaPublicKey;
    }

    public EDDSASigner(SignatureAlgorithm signatureAlgorithm, Certificate certificate) {
        super(signatureAlgorithm);
        this.eddsaPublicKey = certificate.getEddsaPublicKey();
    }    

	@Override
	public String generateSignature(String signingInput) throws SignatureException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean validateSignature(String signingInput, String signature) throws SignatureException {
		// TODO Auto-generated method stub
		return false;
	}

}
