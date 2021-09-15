/**
 * 
 */
package io.jans.as.model.jwt;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.ECDSAPublicKey;
import io.jans.as.model.crypto.signature.EDDSAPublicKey;
import io.jans.as.model.crypto.signature.RSAPublicKey;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.exception.InvalidJwtException;
import io.jans.as.model.jws.ECDSASigner;
import io.jans.as.model.jws.EDDSASigner;
import io.jans.as.model.jws.HMACSigner;
import io.jans.as.model.jws.JwsSigner;
import io.jans.as.model.jws.RSASigner;

/**
 * @author Sergey Manoylo 
 * @version September 6, 2021  
 */
public class JwtVerifier {
    
    @SuppressWarnings("unused")
    private final static Logger log = LoggerFactory.getLogger(JwtVerifier.class);
    
    private AbstractCryptoProvider cryptoProvider;
    
    private JSONObject jwks;

    /**
     * 
     * @param cryptoProvider
     * @param jwks
     */
    public JwtVerifier(final AbstractCryptoProvider cryptoProvider, final  JSONObject jwks) {
        this.cryptoProvider = cryptoProvider;
        this.jwks = jwks;
    }
    
    /**
     * 
     * @param jwt
     * @param clientSecret
     * @return
     * @throws Exception
     */
    public boolean verifyJwt(final Jwt jwt, final String clientSecret) throws Exception {
        
        if(jwt == null) {
            throw new InvalidJwtException("JwtVerifyer: jwt == null (jwt isn't defined)");
        }
        
        String signKeyId = jwt.getHeader().getKeyId();
        
        SignatureAlgorithm signatureAlgorithm = jwt.getHeader().getSignatureAlgorithm();
        if(signatureAlgorithm == null) {
            throw new InvalidJwtException("JwtVerifyer: signatureAlgorithm == null (signatureAlgorithm  isn't defined)");
        }
        
        AlgorithmFamily algFamily = signatureAlgorithm.getFamily();
        
        PublicKey publicKey = null;         
        if(AlgorithmFamily.RSA.equals(algFamily)
                || AlgorithmFamily.EC.equals(algFamily)
                || AlgorithmFamily.ED.equals(algFamily)
                ) {
            if(signKeyId == null) {
                throw new InvalidJwtException("JwtVerifyer: signKeyId == null (signKeyId  isn't defined)");
            }
            publicKey = cryptoProvider.getPublicKey(signKeyId, jwks, null);
            if(publicKey == null) {
                throw new InvalidJwtException("JwtVerifyer: publicKey == null (publicKey isn't  defined)");            
            }            
        }
        
        JwsSigner signer = null;
        
        switch(signatureAlgorithm.getFamily()) {
        case NONE: {
            return true;
        }
        case HMAC: {
            if(clientSecret == null) {
                throw new InvalidJwtException("JwtVerifyer: clientSecret == null (clientSecret isn't  defined)");                
            }
            signer = new HMACSigner(signatureAlgorithm, clientSecret);
            break;
        }
        case RSA: {
            java.security.interfaces.RSAPublicKey jrsaPublicKey = (java.security.interfaces.RSAPublicKey)publicKey;
            RSAPublicKey rsaPublicKey = new RSAPublicKey(jrsaPublicKey.getModulus(), jrsaPublicKey.getPublicExponent());
            signer = new RSASigner(signatureAlgorithm, rsaPublicKey);
            break;
        }
        case EC: {
            ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
            ECDSAPublicKey ecdsaPublicKey = new ECDSAPublicKey(signatureAlgorithm, ecPublicKey.getW().getAffineX(), ecPublicKey.getW().getAffineY());
            signer = new ECDSASigner(signatureAlgorithm, ecdsaPublicKey);
            break;
        }
        case ED: {
            BCEdDSAPublicKey bceddsaPublicKey = (BCEdDSAPublicKey)publicKey;
            EDDSAPublicKey eddsaPublicKey = new EDDSAPublicKey(signatureAlgorithm, bceddsaPublicKey.getEncoded());
            signer = new EDDSASigner(signatureAlgorithm, eddsaPublicKey);
            break;
        }
        default: {
            break;
        }
        }
        
        if(signer == null) {
            throw new InvalidJwtException("JwtVerifyer: signer == null (signer isn't  defined)");
        }
        
        return signer.validate(jwt);
    }

    /**
     * 
     * @param jwt
     * @return
     * @throws Exception
     */
    public boolean verifyJwt(final Jwt jwt) throws Exception {
        return verifyJwt(jwt, null);
    }
    
}
