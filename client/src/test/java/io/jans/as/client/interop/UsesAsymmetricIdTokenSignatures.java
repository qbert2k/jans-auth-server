/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client.interop;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import io.jans.as.client.AuthorizationRequest;
import io.jans.as.client.AuthorizationResponse;
import io.jans.as.client.BaseTest;
import io.jans.as.client.JwkClient;
import io.jans.as.client.RegisterClient;
import io.jans.as.client.RegisterRequest;
import io.jans.as.client.RegisterResponse;
import io.jans.as.model.common.ResponseType;
import io.jans.as.model.crypto.signature.ECDSAPublicKey;
import io.jans.as.model.crypto.signature.EDDSAPublicKey;
import io.jans.as.model.crypto.signature.RSAPublicKey;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jws.ECDSASigner;
import io.jans.as.model.jws.EDDSASigner;
import io.jans.as.model.jws.RSASigner;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtHeaderName;
import io.jans.as.model.register.ApplicationType;
import io.jans.as.model.util.StringUtils;

/**
 * OC5:FeatureTest-Uses Asymmetric ID Token Signatures
 *
 * @author Javier Rojas Blum
 * @version November 3, 2016
 */
public class UsesAsymmetricIdTokenSignatures extends BaseTest {

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesRS256(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures RS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS256);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        RSAPublicKey publicKey = JwkClient.getRSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("rs256: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS256, publicKey);
        assertTrue(rsaSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesRS384(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures RS384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS384);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        RSAPublicKey publicKey = JwkClient.getRSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("rs384: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));          
        
        RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS384, publicKey);
        assertTrue(rsaSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesRS512(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures RS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS512);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        RSAPublicKey publicKey = JwkClient.getRSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("rs512: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS512, publicKey);
        assertTrue(rsaSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesES256(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures ES256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        ECDSAPublicKey publicKey = JwkClient.getECDSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));

        System.out.println("es256: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        ECDSASigner ecdsaSigner = new ECDSASigner(SignatureAlgorithm.ES256, publicKey);
        assertTrue(ecdsaSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesES256K(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures ES256K");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256K);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        ECDSAPublicKey publicKey = JwkClient.getECDSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("es256k: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        ECDSASigner ecdsaSigner = new ECDSASigner(SignatureAlgorithm.ES256K, publicKey);
        assertTrue(ecdsaSigner.validate(jwt));
    }
    
    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesES384(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures ES384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES384);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        ECDSAPublicKey publicKey = JwkClient.getECDSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("es384: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        ECDSASigner ecdsaSigner = new ECDSASigner(SignatureAlgorithm.ES384, publicKey);
        assertTrue(ecdsaSigner.validate(jwt));
    }

    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesES512(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures ES512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES512);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        ECDSAPublicKey publicKey = JwkClient.getECDSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("es512: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        ECDSASigner ecdsaSigner = new ECDSASigner(SignatureAlgorithm.ES512, publicKey);
        assertTrue(ecdsaSigner.validate(jwt));
    }
    
    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesED25519(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures ED25519");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ED25519);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        EDDSAPublicKey publicKey = JwkClient.getEDDSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("ed25519: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        EDDSASigner ecdsaSigner = new EDDSASigner(SignatureAlgorithm.ED25519, publicKey);
        assertTrue(ecdsaSigner.validate(jwt));
    }
    
    @Parameters({"redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri"})
    @Test
    public void usesAsymmetricIdTokenSignaturesED448(
            final String redirectUris, final String userId, final String userSecret, final String redirectUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Uses Asymmetric ID Token Signatures ed448");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.ID_TOKEN);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ED448);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request Authorization
        List<String> scopes = Arrays.asList("openid", "profile", "address", "email");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes, redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(
                authorizationEndpoint, authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        EDDSAPublicKey publicKey = JwkClient.getEDDSAPublicKey(
                jwksUri,
                jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
        
        System.out.println("ed448: key id = " + jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));        
        
        EDDSASigner ecdsaSigner = new EDDSASigner(SignatureAlgorithm.ED448, publicKey);
        assertTrue(ecdsaSigner.validate(jwt));
    }
    
}