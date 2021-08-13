/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.http.HttpStatus;
import org.json.JSONObject;

import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.Use;
import io.jans.eleven.client.DeleteKeyClient;
import io.jans.eleven.client.DeleteKeyRequest;
import io.jans.eleven.client.DeleteKeyResponse;
import io.jans.eleven.client.GenerateKeyClient;
import io.jans.eleven.client.GenerateKeyRequest;
import io.jans.eleven.client.GenerateKeyResponse;
import io.jans.eleven.client.SignClient;
import io.jans.eleven.client.SignRequest;
import io.jans.eleven.client.SignResponse;
import io.jans.eleven.client.VerifySignatureClient;
import io.jans.eleven.client.VerifySignatureRequest;
import io.jans.eleven.client.VerifySignatureResponse;

/**
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public class ElevenCryptoProvider extends AbstractCryptoProvider {

    private String generateKeyEndpoint;
    private String signEndpoint;
    private String verifySignatureEndpoint;
    private String deleteKeyEndpoint;
    private String accessToken;

    public ElevenCryptoProvider(String generateKeyEndpoint, String signEndpoint, String verifySignatureEndpoint,
                                String deleteKeyEndpoint, String accessToken) {
        this.generateKeyEndpoint = generateKeyEndpoint;
        this.signEndpoint = signEndpoint;
        this.verifySignatureEndpoint = verifySignatureEndpoint;
        this.deleteKeyEndpoint = deleteKeyEndpoint;
        this.accessToken = accessToken;
    }

    @Override
    public boolean containsKey(String keyId) {
        return false;
    }

    @Override
    public JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use) throws Exception {
        GenerateKeyRequest request = new GenerateKeyRequest();
        request.setSignatureAlgorithm(algorithm.toString());
        request.setExpirationTime(expirationTime);
        request.setAccessToken(accessToken);

        GenerateKeyClient client = new GenerateKeyClient(generateKeyEndpoint);
        client.setRequest(request);

        GenerateKeyResponse response = client.exec();
        if (response.getStatus() == HttpStatus.SC_OK && response.getKeyId() != null) {
            return response.getJSONEntity();
        } else {
            throw new Exception(response.getEntity());
        }
    }

    @Override
    public String sign(String signingInput, String keyId, String shardSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        SignRequest request = new SignRequest();
        request.getSignRequestParam().setSigningInput(signingInput);
        request.getSignRequestParam().setAlias(keyId);
        request.getSignRequestParam().setSharedSecret(shardSecret);
        request.getSignRequestParam().setSignatureAlgorithm(signatureAlgorithm.getName());
        request.setAccessToken(accessToken);

        SignClient client = new SignClient(signEndpoint);
        client.setRequest(request);

        SignResponse response = client.exec();
        if (response.getStatus() == HttpStatus.SC_OK && response.getSignature() != null) {
            return response.getSignature();
        } else {
            throw new Exception(response.getEntity());
        }
    }

    @Override
    public boolean verifySignature(String signingInput, String encodedSignature, String keyId, JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        VerifySignatureRequest request = new VerifySignatureRequest();
        request.getVerifySignatureRequestParam().setSigningInput(signingInput);
        request.getVerifySignatureRequestParam().setSignature(encodedSignature);
        request.getVerifySignatureRequestParam().setAlias(keyId);
        request.getVerifySignatureRequestParam().setSharedSecret(sharedSecret);
        request.getVerifySignatureRequestParam().setSignatureAlgorithm(signatureAlgorithm.getName());
        request.setAccessToken(accessToken);
        if (jwks != null) {
            request.getVerifySignatureRequestParam().setJwksRequestParam(getJwksRequestParam(jwks));
        }

        VerifySignatureClient client = new VerifySignatureClient(verifySignatureEndpoint);
        client.setRequest(request);

        VerifySignatureResponse response = client.exec();
        if (response.getStatus() == HttpStatus.SC_OK) {
            return response.isVerified();
        } else {
            throw new Exception(response.getEntity());
        }
    }

    @Override
    public boolean deleteKey(String keyId) throws Exception {
        DeleteKeyRequest request = new DeleteKeyRequest();
        request.setAlias(keyId);
        request.setAccessToken(accessToken);

        DeleteKeyClient client = new DeleteKeyClient(deleteKeyEndpoint);
        client.setRequest(request);

        DeleteKeyResponse response = client.exec();
        if (response.getStatus() == org.apache.http.HttpStatus.SC_OK) {
            return response.isDeleted();
        } else {
            throw new Exception(response.getEntity());
        }
    }

	@Override
	public PrivateKey getPrivateKey(String keyId) {
        throw new UnsupportedOperationException("Method not implemented.");
	}

    @Override
    public PublicKey getPublicKey(String keyId) {
        throw new UnsupportedOperationException("Method not implemented.");
    }
	
}