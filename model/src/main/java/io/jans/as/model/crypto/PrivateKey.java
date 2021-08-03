/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.crypto;

import io.jans.as.model.common.JSONable;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;

/**
 * The Private Key for Cryptography algorithms
 *
 * @author Javier Rojas Blum
 * @version June 25, 2016
 */
public abstract class PrivateKey implements JSONable {

    private String keyId;

    private SignatureAlgorithm signatureAlgorithm;
    
    /**
     * 
     * @param keyId
     * @param signatureAlgorithm
     */
    protected PrivateKey (String keyId, SignatureAlgorithm signatureAlgorithm) {
        this.keyId = keyId;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * 
     * @return
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * 
     * @param keyId
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * 
     * @return
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * 
     * @param signatureAlgorithm
     */
    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

}
