/**
 * 
 */
package io.jans.as.model.jwe;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.signature.ECDSAPublicKey;
import io.jans.as.model.crypto.signature.EDDSAPublicKey;
import io.jans.as.model.crypto.signature.RSAPublicKey;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jws.ECDSASigner;
import io.jans.as.model.jws.EDDSASigner;
import io.jans.as.model.jws.JwsSigner;
import io.jans.as.model.jws.RSASigner;
import io.jans.as.model.jwt.Jwt;


/**
 * @author Sergey Manoylo 
 * @version September 6, 2021  
 */
public class JweVerifyer {
    
    @SuppressWarnings("unused")
    private final static Logger log = LoggerFactory.getLogger(JweVerifyer.class);
    
    private AbstractCryptoProvider cryptoProvider;
    
    private JSONObject jwks;

    /**
     * 
     * @param cryptoProvider
     * @param jwks
     */
    public JweVerifyer(final AbstractCryptoProvider cryptoProvider, final  JSONObject jwks) {
        this.cryptoProvider = cryptoProvider;
        this.jwks = jwks;
    }

    /**
     * 
     * @param jwe
     * @return
     * @throws Exception 
     */
    public boolean verifyJwe(final Jwe jwe) throws Exception {
        boolean verifyingRes = false;
        
        String signKeyId = jwe.getSignedJWTPayload().getHeader().getKeyId();
        
        SignatureAlgorithm signatureAlgorithm = jwe.getSignedJWTPayload().getHeader().getSignatureAlgorithm();
        
        Jwt signedJwt = jwe.getSignedJWTPayload();
        
        PublicKey publicKey = cryptoProvider.getPublicKey(signKeyId, jwks, null);
        
        JwsSigner signer = null;
        
        switch(signatureAlgorithm.getFamily()) {
        case HMAC: {
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
            signer = new ECDSASigner(jwe.getSignedJWTPayload().getHeader().getSignatureAlgorithm(), ecdsaPublicKey);
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
        
        if(signer != null) {
            verifyingRes = signer.validate(signedJwt);               
        }

/*        
case RSA: {
    RSAPublicKey publicKey = JwkClient.getRSAPublicKey(client.getJwksUri(), keyId);
    RSASigner rsaSigner = new RSASigner(algorithm, publicKey);
    validSignature = rsaSigner.validate(jwt);       

    
    
        public enum AlgorithmFamily {
            HMAC("HMAC"),
            RSA("RSA"),
            EC("EC"),
            ED("ED"),
            AES("AES"),
            PASSW("PASSW");        
        
        
        signatureAlgorithm.getFamily()
        
        switch(signatureAlgorithm) {
        case NONE: {
            break;
        }
        case HS256:
        case HS384:
        case HS512: {
            break;
        }
        case RS256:
        case RS384:
        case RS512:
        case PS256:
        case PS384:
        case PS512: {
            break;
        }
        case ES256:
        case ES256K:            
        case ES384:            
        case ES512: {
            PublicKey publicKey = cryptoProvider.getPublicKey(signKeyId, jwks, null);
            ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
            ECDSAPublicKey ecdsaPublicKey = new ECDSAPublicKey(signatureAlgorithm, ecPublicKey.getW().getAffineX(), ecPublicKey.getW().getAffineY());
            ECDSASigner ecdsaSigner = new ECDSASigner(jwe.getSignedJWTPayload().getHeader().getSignatureAlgorithm(), ecdsaPublicKey);
            verifyingRes = ecdsaSigner.validate(signedJwt);            
            break;
        }
        case ED25519:
        case ED448:
        case EDDSA: {
            break;
        }
        default: {
            break;
        }            
        }
*/
/*
        NONE("none"),
        
        HS256("HS256", AlgorithmFamily.HMAC, "HMACSHA256", JWSAlgorithm.HS256),
        HS384("HS384", AlgorithmFamily.HMAC, "HMACSHA384", JWSAlgorithm.HS384),
        HS512("HS512", AlgorithmFamily.HMAC, "HMACSHA512", JWSAlgorithm.HS512),
        
        RS256("RS256", AlgorithmFamily.RSA, "SHA256WITHRSA", JWSAlgorithm.RS256),
        RS384("RS384", AlgorithmFamily.RSA, "SHA384WITHRSA", JWSAlgorithm.RS384),
        RS512("RS512", AlgorithmFamily.RSA, "SHA512WITHRSA", JWSAlgorithm.RS512),
        
        ES256("ES256", AlgorithmFamily.EC, "SHA256WITHECDSA",   EllipticEdvardsCurve.P_256,     JWSAlgorithm.ES256),
        ES256K("ES256K", AlgorithmFamily.EC, "SHA256WITHECDSA", EllipticEdvardsCurve.P_256K,    JWSAlgorithm.ES256K),
        ES384("ES384", AlgorithmFamily.EC, "SHA384WITHECDSA",   EllipticEdvardsCurve.P_384,     JWSAlgorithm.ES384),
        ES512("ES512", AlgorithmFamily.EC, "SHA512WITHECDSA",   EllipticEdvardsCurve.P_521,     JWSAlgorithm.ES512),
        
        PS256("PS256", AlgorithmFamily.RSA, "SHA256withRSAandMGF1", JWSAlgorithm.PS256),
        PS384("PS384", AlgorithmFamily.RSA, "SHA384withRSAandMGF1", JWSAlgorithm.PS384),
        PS512("PS512", AlgorithmFamily.RSA, "SHA512withRSAandMGF1", JWSAlgorithm.PS512),
        
        ED25519("Ed25519",  AlgorithmFamily.ED, "Ed25519",  EllipticEdvardsCurve.ED_25519,  JWSAlgorithm.EdDSA),
        ED448("Ed448",      AlgorithmFamily.ED, "Ed448",    EllipticEdvardsCurve.ED_448,    JWSAlgorithm.EdDSA),
        EDDSA("EdDSA",      AlgorithmFamily.ED, "Ed25519",  EllipticEdvardsCurve.ED_25519,  JWSAlgorithm.EdDSA);        
  */      
        return verifyingRes;
    }
    
}
