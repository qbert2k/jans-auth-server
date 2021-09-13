/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client.interop;

import io.jans.as.client.AuthorizationRequest;
import io.jans.as.client.AuthorizationResponse;
import io.jans.as.client.BaseTest;
import io.jans.as.client.RegisterClient;
import io.jans.as.client.RegisterRequest;
import io.jans.as.client.RegisterResponse;
import io.jans.as.model.common.GrantType;
import io.jans.as.model.common.ResponseType;
import io.jans.as.model.common.SubjectType;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtVerifyer;
import io.jans.as.model.register.ApplicationType;
import io.jans.as.model.util.JwtUtil;
import io.jans.as.model.util.StringUtils;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature
 *
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public class AcceptValidAsymmetricIdTokenSignature extends BaseTest {

    @Parameters({ "redirectUris", "userId", "userSecret", "redirectUri", "sectorIdentifierUri" })
    @Test
    public void acceptValidAsymmetricIdTokenSignatureRS256(final String redirectUris, final String userId,
            final String userSecret, final String redirectUri, final String sectorIdentifierUri) throws Exception {
        showTitle("OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature RS256");

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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        JwtVerifyer jwtVerifyer = new JwtVerifyer(new AuthCryptoProvider(), JwtUtil.getJSONWebKeys(jwksUri));
        assertTrue(jwtVerifyer.verifyJwt(jwt));
    }

    @Parameters({ "redirectUris", "userId", "userSecret", "redirectUri", "postLogoutRedirectUri", "clientJwksUri" })
    @Test
    public void acceptValidAsymmetricIdTokenSignatureES256(final String redirectUris, final String userId,
            final String userSecret, final String redirectUri, final String postLogoutRedirectUri,
            final String clientJwksUri) throws Exception {
        showTitle("OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature es256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN);

        List<GrantType> grantTypes = Arrays.asList(GrantType.AUTHORIZATION_CODE);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, null,
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256);
        registerRequest.setPostLogoutRedirectUris(StringUtils.spaceSeparatedToList(postLogoutRedirectUri));
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setRequireAuthTime(true);
        registerRequest.setDefaultMaxAge(3600);
        registerRequest.setGrantTypes(grantTypes);

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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        JwtVerifyer jwtVerifyer = new JwtVerifyer(new AuthCryptoProvider(), JwtUtil.getJSONWebKeys(jwksUri));
        assertTrue(jwtVerifyer.verifyJwt(jwt));
    }

    @Parameters({ "redirectUris", "userId", "userSecret", "redirectUri", "postLogoutRedirectUri", "clientJwksUri" })
    @Test
    public void acceptValidAsymmetricIdTokenSignatureES256K(final String redirectUris, final String userId,
            final String userSecret, final String redirectUri, final String postLogoutRedirectUri,
            final String clientJwksUri) throws Exception {
        showTitle("OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature es256k");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN);

        List<GrantType> grantTypes = Arrays.asList(GrantType.AUTHORIZATION_CODE);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, null,
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256K);
        registerRequest.setPostLogoutRedirectUris(StringUtils.spaceSeparatedToList(postLogoutRedirectUri));
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setRequireAuthTime(true);
        registerRequest.setDefaultMaxAge(3600);
        registerRequest.setGrantTypes(grantTypes);

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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        JwtVerifyer jwtVerifyer = new JwtVerifyer(new AuthCryptoProvider(), JwtUtil.getJSONWebKeys(jwksUri));
        assertTrue(jwtVerifyer.verifyJwt(jwt));
    }

    @Parameters({ "redirectUris", "userId", "userSecret", "redirectUri", "postLogoutRedirectUri", "clientJwksUri" })
    @Test
    public void acceptValidAsymmetricIdTokenSignatureED25519(final String redirectUris, final String userId,
            final String userSecret, final String redirectUri, final String postLogoutRedirectUri,
            final String clientJwksUri) throws Exception {
        showTitle("OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature ed25519");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN);

        List<GrantType> grantTypes = Arrays.asList(GrantType.AUTHORIZATION_CODE);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, null,
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ED25519);
        registerRequest.setPostLogoutRedirectUris(StringUtils.spaceSeparatedToList(postLogoutRedirectUri));
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setRequireAuthTime(true);
        registerRequest.setDefaultMaxAge(3600);
        registerRequest.setGrantTypes(grantTypes);

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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        JwtVerifyer jwtVerifyer = new JwtVerifyer(new AuthCryptoProvider(), JwtUtil.getJSONWebKeys(jwksUri));
        assertTrue(jwtVerifyer.verifyJwt(jwt));
    }

    @Parameters({ "redirectUris", "userId", "userSecret", "redirectUri", "postLogoutRedirectUri", "clientJwksUri" })
    @Test
    public void acceptValidAsymmetricIdTokenSignatureED448(final String redirectUris, final String userId,
            final String userSecret, final String redirectUri, final String postLogoutRedirectUri,
            final String clientJwksUri) throws Exception {
        showTitle("OC5:FeatureTest-Accept Valid Asymmetric ID Token Signature ed448");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.CODE, ResponseType.ID_TOKEN);

        List<GrantType> grantTypes = Arrays.asList(GrantType.AUTHORIZATION_CODE);

        // 1. Registration
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, null,
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ED448);
        registerRequest.setPostLogoutRedirectUris(StringUtils.spaceSeparatedToList(postLogoutRedirectUri));
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setSubjectType(SubjectType.PUBLIC);
        registerRequest.setRequireAuthTime(true);
        registerRequest.setDefaultMaxAge(3600);
        registerRequest.setGrantTypes(grantTypes);

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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation());
        assertNotNull(authorizationResponse.getIdToken());
        assertNotNull(authorizationResponse.getState());
        assertEquals(authorizationResponse.getState(), state);

        String idToken = authorizationResponse.getIdToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        JwtVerifyer jwtVerifyer = new JwtVerifyer(new AuthCryptoProvider(), JwtUtil.getJSONWebKeys(jwksUri));
        assertTrue(jwtVerifyer.verifyJwt(jwt));
    }

}