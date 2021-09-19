/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2021, Janssen Project
 */
package io.jans.as.model.crypto.signature;

import static io.jans.as.model.jwk.JWKParameter.EXPONENT;
import static io.jans.as.model.jwk.JWKParameter.MODULUS;
import static io.jans.as.model.jwk.JWKParameter.D;
import static io.jans.as.model.jwk.JWKParameter.X;

import java.io.IOException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.crypto.PrivateKey;
import io.jans.as.model.util.Base64Util;
import io.jans.as.model.util.StringUtils;

/**
 * 
 *
 * @author Sergey Manoylo
 * @version July 23, 2021
 */
public class EDDSAPrivateKey extends PrivateKey {

    private byte[] dEncoded;
    private byte[] xEncoded;

    /**
     * Constructor
     * @param signatureAlgorithm
     * @param dEncoded
     * @param xEncoded
     */
    public EDDSAPrivateKey(SignatureAlgorithm signatureAlgorithm, byte[] dEncoded, byte[] xEncoded) {
        super(null, signatureAlgorithm);
        this.dEncoded = dEncoded.clone();
        this.xEncoded = xEncoded.clone();
    }
    
    /**
     * Copy Constructor
     * @param eddsaPrivateKey
     */
    public EDDSAPrivateKey(final EDDSAPrivateKey eddsaPrivateKey) {
        super(null, eddsaPrivateKey.getSignatureAlgorithm());

        final byte[] dEncoded = eddsaPrivateKey.getPrivateKeyEncoded();
        final byte[] xEncoded = eddsaPrivateKey.getPublicKeyEncoded();

        this.dEncoded = dEncoded != null ? dEncoded.clone() : null;
        this.xEncoded = xEncoded != null ? xEncoded.clone() : null;
    }

    /**
     * get public key value array (PKCS8 encoded, Private-Key Information Syntax Standard) 
     * in PKCS8EncodedKeySpec object;
     * PKCS8EncodedKeySpec allows to get encoded array (byte[] getEncoded());
     * 
     * @return public key value array (PKCS8 encoded, Private-Key Information Syntax Standard)
     * in PKCS8EncodedKeySpec object;
     * PKCS8EncodedKeySpec allows to get encoded array (byte[] getEncoded()); 
     */
    public PKCS8EncodedKeySpec getPrivateKeySpec() {
        return new PKCS8EncodedKeySpec(this.dEncoded);
    }
    
    /**
     * get public key value array (X509 encoded) in X509EncodedKeySpec object;
     * X509EncodedKeySpec allows to get encoded array (byte[]);
     * 
     * @return public key value array (X509 encoded) in X509EncodedKeySpec object;
     * X509EncodedKeySpec allows to get encoded array (byte[]);
     */
    public X509EncodedKeySpec getPublicKeySpec() {
        if(this.xEncoded == null)
            return null;
        else
            return new X509EncodedKeySpec(this.xEncoded);
    }

    /**
     * get original array (decoded) of the public key (ED25519 - 32 byte, ED448 - 56 bytes);
     * 
     * @return original array (decoded) of the public key (ED25519 - 32 byte, ED448 - 56 bytes);
     * @throws IOException
     */
    public byte[] getPrivateKeyDecoded() throws IOException {
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(new PKCS8EncodedKeySpec(this.dEncoded).getEncoded());
        return ASN1OctetString.getInstance(pki.parsePrivateKey()).getOctets();        
    }
    
    /**
     * 
     * @return
     */
    public byte[] getPrivateKeyEncoded() {
        return this.dEncoded;
    }

    /**
     * get original array (decoded) of the public key (ED25519 - 32 byte, ED448 - 56 bytes);
     * 
     * @return original array (decoded) of the public key (ED25519 - 32 byte, ED448 - 56 bytes);
     */
    public byte[] getPublicKeyDecoded() {
        SubjectPublicKeyInfo subjPubKeyInfo = SubjectPublicKeyInfo.getInstance(this.xEncoded);
        return subjPubKeyInfo.getPublicKeyData().getOctets();       
    }

    /**
     * 
     * @return
     */
    public byte[] getPublicKeyEncoded() {
        return this.xEncoded;
    }

    /**
     * 
     */
    @Override
    public JSONObject toJSONObject() throws JSONException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(MODULUS, JSONObject.NULL);
        jsonObject.put(EXPONENT, JSONObject.NULL);
        jsonObject.put(D, Base64Util.base64urlencode(this.dEncoded));
        jsonObject.put(X, Base64Util.base64urlencode(this.xEncoded));
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
    public EDDSAPrivateKey clone() {
        return new EDDSAPrivateKey(getSignatureAlgorithm(), this.dEncoded, this.xEncoded);
    }

    /**
     * 
     */
    @Override
    public boolean equals(Object obj) {
        if(this == obj) {
            return true;            
        }
        if(obj == null) {
            return false;
        }
        if(this.getClass() != obj.getClass()) {
            return false;
        }
        EDDSAPrivateKey objTyped = (EDDSAPrivateKey) obj;

        if(!Arrays.equals(this.xEncoded, objTyped.xEncoded)) {
            return false;
        }

        if(!Arrays.equals(this.dEncoded, objTyped.dEncoded)) {
            return false;
        }
        
        String thisKeyId = getKeyId();
        String objKeyId = objTyped.getKeyId();        

        SignatureAlgorithm thisSignAlg = this.getSignatureAlgorithm();        
        SignatureAlgorithm objSignAlg = objTyped.getSignatureAlgorithm();
        
        boolean keysEquals = (thisKeyId == null && objKeyId == null) ||
                (thisKeyId != null && thisKeyId.equals(objKeyId));

        boolean signAlgEquals = (thisSignAlg == null && objSignAlg == null) ||
                (thisSignAlg != null && thisSignAlg.equals(objSignAlg));

        return keysEquals && signAlgEquals;         
    }

    /**
     * 
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(this.dEncoded) ^ Arrays.hashCode(this.xEncoded);         
    }
}
