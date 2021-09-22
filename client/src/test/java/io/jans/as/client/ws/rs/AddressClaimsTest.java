/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client.ws.rs;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.json.JSONObject;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import io.jans.as.client.AuthorizationRequest;
import io.jans.as.client.AuthorizationResponse;
import io.jans.as.client.AuthorizeClient;
import io.jans.as.client.BaseTest;
import io.jans.as.client.JwkClient;
import io.jans.as.client.JwkResponse;
import io.jans.as.client.RegisterClient;
import io.jans.as.client.RegisterRequest;
import io.jans.as.client.RegisterResponse;
import io.jans.as.client.UserInfoClient;
import io.jans.as.client.UserInfoRequest;
import io.jans.as.client.UserInfoResponse;
import io.jans.as.client.model.authorize.Claim;
import io.jans.as.client.model.authorize.ClaimValue;
import io.jans.as.client.model.authorize.JwtAuthorizationRequest;
import io.jans.as.model.common.ResponseType;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.encryption.BlockEncryptionAlgorithm;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwe.Jwe;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwt.JwtVerifier;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtClaimName;
import io.jans.as.model.jwt.JwtHeaderName;
import io.jans.as.model.register.ApplicationType;
import io.jans.as.model.util.JwtUtil;
import io.jans.as.model.util.StringUtils;

/**
 * Note: In order to run this tests, set legacyIdTokenClaims to true.
 *
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public class AddressClaimsTest extends BaseTest {

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "RS256_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestDefault(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestDefault");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.RS256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequestHS256(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequestHS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.HS256);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.HS256);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.HS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.HS256, clientSecret, cryptoProvider);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt, clientSecret));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequestHS384(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequestHS384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.HS384);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.HS384);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.HS384);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.HS384, clientSecret, cryptoProvider);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt, clientSecret));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequestHS512(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequestHS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.HS512);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.HS512);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.HS512, clientSecret, cryptoProvider);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt, clientSecret));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "RS256_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestRS256(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestRS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS256);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.RS256);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.RS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");
        registerRequest.setJwksUri(clientJwksUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.RS256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "RS384_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestRS384(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestRS384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS384);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.RS384);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.RS384);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");
        registerRequest.setJwksUri(clientJwksUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.RS384, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "RS512_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestRS512(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestRS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS512);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.RS512);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.RS512);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.RS512, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));

        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "ES256_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestES256(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestES256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.ES256);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.ES256);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.ES256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));

        jwtAuthorizationRequest.addUserInfoClaim(new Claim(JwtClaimName.NAME, ClaimValue.createEssential(true)));

        jwtAuthorizationRequest.addUserInfoClaim(new Claim(JwtClaimName.NAME, ClaimValue.createEssential(true)));

        jwtAuthorizationRequest.addUserInfoClaim(new Claim(JwtClaimName.GIVEN_NAME, ClaimValue.createEssential(true)));

        jwtAuthorizationRequest.addUserInfoClaim(new Claim(JwtClaimName.FAMILY_NAME, ClaimValue.createEssential(true)));

        jwtAuthorizationRequest.addUserInfoClaim(new Claim(JwtClaimName.MIDDLE_NAME, ClaimValue.createEssential(true)));

        jwtAuthorizationRequest.addUserInfoClaim(new Claim(JwtClaimName.NICKNAME, ClaimValue.createEssential(true)));

        jwtAuthorizationRequest.addUserInfoClaim(new Claim(JwtClaimName.USER_NAME, ClaimValue.createEssential(true)));

        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);

        System.out.println("JwtClaimName.ISSUER         = " + jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        System.out.println("JwtClaimName.NAME           = " + jwt.getClaims().getClaimAsString(JwtClaimName.NAME));
        System.out.println(
                "JwtClaimName.GIVEN_NAME       = " + jwt.getClaims().getClaimAsString(JwtClaimName.GIVEN_NAME));
        System.out.println(
                "JwtClaimName.FAMILY_NAME      = " + jwt.getClaims().getClaimAsString(JwtClaimName.FAMILY_NAME));
        System.out.println(
                "JwtClaimName.MIDDLE_NAME      = " + jwt.getClaims().getClaimAsString(JwtClaimName.MIDDLE_NAME));
        System.out.println("JwtClaimName.NICKNAME       = " + jwt.getClaims().getClaimAsString(JwtClaimName.NICKNAME));
        System.out.println("JwtClaimName.USER_NAME      = " + jwt.getClaims().getClaimAsString(JwtClaimName.USER_NAME));

        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "ES256K_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestES256K(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestES256K");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES256K);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.ES256K);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.ES256K);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.ES256K, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "ES384_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestES384(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestES384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES384);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.ES384);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.ES384);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.ES384, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "ES512_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestES512(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestES512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ES512);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.ES512);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.ES512);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.ES512, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "PS256_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestPS256(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestPS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.PS256);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.PS256);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.PS256);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.PS256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "PS384_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestPS384(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestPS384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.PS384);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.PS384);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.PS384);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.PS384, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "PS512_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestPS512(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestPS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.PS512);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.PS512);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.PS512);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.PS512, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "Ed25519_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestED25519(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestED25519");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ED25519);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.ED25519);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.ED25519);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.ED25519, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri", "Ed448_keyId", "clientJwksUri" })
    @Test
    public void authorizationRequestED448(final String userId, final String userSecret, final String redirectUri,
            final String redirectUris, final String dnName, final String keyStoreFile, final String keyStoreSecret,
            final String sectorIdentifierUri, final String keyId, final String clientJwksUri) throws Exception {
        showTitle("authorizationRequestED448");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.ED448);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.ED448);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.ED448);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                SignatureAlgorithm.ED448, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(keyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwt jwt = Jwt.parse(idToken);
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwt.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwt));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setJwksUri(jwksUri);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgA128KW_EncA128GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgA128KW_EncA128GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.A128KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A128KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.A128KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.A128KW, BlockEncryptionAlgorithm.A128GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgA256KW_EncA256GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgA256KW_EncA256GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.A256KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A256KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.A256KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.A256KW, BlockEncryptionAlgorithm.A256GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgA128GCMKW_EncA128GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgA128GCMKW_EncA128GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.A128GCMKW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A128GCMKW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.A128GCMKW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.A128GCMKW, BlockEncryptionAlgorithm.A128GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgA256GCMKW_EncA256GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgA256GCMKW_EncA256GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.A256GCMKW, BlockEncryptionAlgorithm.A256GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgA256GCMKW_EncA256CBC_HS512(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgA256GCMKW_EncA256CBC_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.A256GCMKW, BlockEncryptionAlgorithm.A256CBC_HS512, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgA256GCMKW_EncA256CBC_PLUS_HS512(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgA256GCMKW_EncA256CBC_PLUS_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.A256GCMKW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.A256GCMKW, BlockEncryptionAlgorithm.A256CBC_PLUS_HS512, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt();
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 3. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 4. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "RSA1_5_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgRSA15_EncA128CBCPLUSHS256(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgRSA15_EncA128CBCPLUSHS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA1_5);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA1_5);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.RSA1_5);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.RSA1_5);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.RSA1_5, BlockEncryptionAlgorithm.A128CBC_PLUS_HS256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "RSA1_5_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgRSA15_EncA256CBCPLUSHS512(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgRSA15_EncA256CBCPLUSHS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA1_5);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA1_5);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.RSA1_5);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.RSA1_5);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.RSA1_5, BlockEncryptionAlgorithm.A256CBC_PLUS_HS512, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "RSA_OAEP_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgRSAOAEP_EncA256GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgRSAOAEP_EncA256GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.RSA_OAEP);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.RSA_OAEP, BlockEncryptionAlgorithm.A256GCM, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "RSA_OAEP_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgRSAOAEP_EncA128CBC_HS256(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgRSAOAEP_EncA128CBC_HS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.RSA_OAEP);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.RSA_OAEP, BlockEncryptionAlgorithm.A128CBC_HS256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "RSA_OAEP_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgRSAOAEP_EncA192CBC_HS384(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgRSAOAEP_EncA192CBC_HS384");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A192CBC_HS384);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A192CBC_HS384);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A192CBC_HS384);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.RSA_OAEP);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.RSA_OAEP, BlockEncryptionAlgorithm.A192CBC_HS384, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "RSA_OAEP_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgRSAOAEP_EncA256CBC_HS512(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgRSAOAEP_EncA256CBC_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.RSA_OAEP);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.RSA_OAEP);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.RSA_OAEP, BlockEncryptionAlgorithm.A256CBC_HS512, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "ECDH_ES_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgECDH_ES_EncA128CBC_HS256(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgECDH_ES_EncA128CBC_HS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.ECDH_ES);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.ECDH_ES, BlockEncryptionAlgorithm.A128CBC_HS256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "ECDH_ES_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgECDH_ES_EncA256GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgECDH_ES_EncA256GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.ECDH_ES);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.ECDH_ES, BlockEncryptionAlgorithm.A256GCM, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "ECDH_ES_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgECDH_ES_EncA256CBC_PLUS_HS512(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String dnName, final String keyStoreFile,
            final String keyStoreSecret, final String clientKeyId, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgECDH_ES_EncA256CBC_PLUS_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.ECDH_ES);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.ECDH_ES);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.ECDH_ES, BlockEncryptionAlgorithm.A256CBC_PLUS_HS512, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));

        try {
            @SuppressWarnings("unused")
            String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
            assertTrue(false);
        } catch (Exception e) {
            // KeyEncryptionAlgorithm.DIR and BlockEncryptionAlgorithm.A128CBC_PLUS_HS256
            // KeyEncryptionAlgorithm.DIR and BlockEncryptionAlgorithm.A128CBC_PLUS_HS256
            // can't be used together
            // BlockEncryptionAlgorithm.A128CBC_PLUS_HS256 and
            // BlockEncryptionAlgorithm.A128CBC_PLUS_HS256
            // only with key encryption/wrap mode (for example,
            // KeyEncryptionAlgorithm.A128KW)
            assertTrue(true);
        }
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "ECDH_ES_PLUS_A128KW_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgECDH_ES_PLUS_A128KW_EncA128CBC_HS256(final String userId,
            final String userSecret, final String redirectUri, final String redirectUris, final String dnName,
            final String keyStoreFile, final String keyStoreSecret, final String clientKeyId,
            final String clientJwksUri, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgECDH_ES_PLUS_A128KW_EncA128CBC_HS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.ECDH_ES_PLUS_A128KW);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW, BlockEncryptionAlgorithm.A128CBC_HS256, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "ECDH_ES_PLUS_A128KW_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgECDH_ES_PLUS_A128KW_EncA256CBC_HS512(final String userId,
            final String userSecret, final String redirectUri, final String redirectUris, final String dnName,
            final String keyStoreFile, final String keyStoreSecret, final String clientKeyId,
            final String clientJwksUri, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgECDH_ES_PLUS_A128KW_EncA256CBC_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.ECDH_ES_PLUS_A128KW);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW, BlockEncryptionAlgorithm.A256CBC_HS512, cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "dnName", "keyStoreFile", "keyStoreSecret",
            "ECDH_ES_PLUS_A128KW_keyId", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgECDH_ES_PLUS_A128KW_EncA256CBC_PLUS_HS512(final String userId,
            final String userSecret, final String redirectUri, final String redirectUris, final String dnName,
            final String keyStoreFile, final String keyStoreSecret, final String clientKeyId,
            final String clientJwksUri, final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgECDH_ES_PLUS_A128KW_EncA256CBC_PLUS_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();

        // 2. Choose encryption key
        JwkClient jwkClient = new JwkClient(jwksUri);
        JwkResponse jwkResponse = jwkClient.exec();
        String serverKeyId = jwkResponse.getKeyId(Algorithm.ECDH_ES_PLUS_A128KW);
        assertNotNull(serverKeyId);

        // 3. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.ECDH_ES_PLUS_A128KW, BlockEncryptionAlgorithm.A256CBC_PLUS_HS512,
                cryptoProvider);
        jwtAuthorizationRequest.setKeyId(serverKeyId);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        PrivateKey privateKey = cryptoProvider.getPrivateKey(clientKeyId);

        Jwe jwe = Jwe.parse(idToken, privateKey, null);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(cryptoProvider, jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setPrivateKey(privateKey);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgDir_EncA128GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgDir_EncA128GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.DIR, BlockEncryptionAlgorithm.A128GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgDir_EncA128CBC_HS256(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgDir_EncA128CBC_HS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128CBC_HS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.DIR, BlockEncryptionAlgorithm.A128CBC_HS256, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgDir_EncA128CBC_PLUS_HS256(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgDir_EncA128CBC_PLUS_HS256");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.DIR, BlockEncryptionAlgorithm.A128CBC_PLUS_HS256, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));

        try {
            @SuppressWarnings("unused")
            String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
            assertTrue(false);
        } catch (Exception e) {
            // KeyEncryptionAlgorithm.DIR and BlockEncryptionAlgorithm.A128CBC_PLUS_HS256
            // KeyEncryptionAlgorithm.DIR and BlockEncryptionAlgorithm.A128CBC_PLUS_HS256
            // can't be used together
            // BlockEncryptionAlgorithm.A128CBC_PLUS_HS256 and
            // BlockEncryptionAlgorithm.A128CBC_PLUS_HS256
            // only with key encryption/wrap mode (for example,
            // KeyEncryptionAlgorithm.A128KW)
            assertTrue(true);
        }
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgDir_EncA256GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgDir_EncA256GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.DIR, BlockEncryptionAlgorithm.A256GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgDir_EncA256CBC_HS512(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgDir_EncA256CBC_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.DIR);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.DIR, BlockEncryptionAlgorithm.A256CBC_HS512, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, clientSecret.getBytes(StandardCharsets.UTF_8));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedKey(clientSecret.getBytes(StandardCharsets.UTF_8));
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgPBES2_HS256_PLUS_A128KW_EncA128GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgPBES2_HS256_PLUS_A128KW_EncA128GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.PBES2_HS256_PLUS_A128KW, BlockEncryptionAlgorithm.A128GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, null, clientSecret);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedPassword(clientSecret);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgPBES2_HS512_PLUS_A256KW_EncA256GCM(final String userId, final String userSecret,
            final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgPBES2_HS512_PLUS_A256KW_EncA256GCM");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256GCM);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW, BlockEncryptionAlgorithm.A256GCM, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, null, clientSecret);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedPassword(clientSecret);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgPBES2_HS384_PLUS_A192KW_EncA256CBC_HS512(final String userId,
            final String userSecret, final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgPBES2_HS384_PLUS_A192KW_EncA256CBC_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.PBES2_HS384_PLUS_A192KW, BlockEncryptionAlgorithm.A256CBC_HS512, clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, null, clientSecret);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedPassword(clientSecret);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

    @Parameters({ "userId", "userSecret", "redirectUri", "redirectUris", "clientJwksUri", "sectorIdentifierUri" })
    @Test
    public void authorizationRequest_AlgPBES2_HS512_PLUS_A256KW_EncA256CBC_PLUS_HS512(final String userId,
            final String userSecret, final String redirectUri, final String redirectUris, final String clientJwksUri,
            final String sectorIdentifierUri) throws Exception {
        showTitle("authorizationRequest_AlgPBES2_HS512_PLUS_A256KW_EncA256CBC_PLUS_HS512");

        List<ResponseType> responseTypes = Arrays.asList(ResponseType.TOKEN, ResponseType.ID_TOKEN);

        // 1. Register client
        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "jans test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setResponseTypes(responseTypes);
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setJwksUri(clientJwksUri);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.addCustomAttribute("jansInclClaimsInIdTkn", "true");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse registerResponse = registerClient.exec();

        showClient(registerClient);
        assertEquals(registerResponse.getStatus(), 201, "Unexpected response code: " + registerResponse.getEntity());
        assertNotNull(registerResponse.getClientId());
        assertNotNull(registerResponse.getClientSecret());
        assertNotNull(registerResponse.getRegistrationAccessToken());
        assertNotNull(registerResponse.getClientIdIssuedAt());
        assertNotNull(registerResponse.getClientSecretExpiresAt());

        String clientId = registerResponse.getClientId();
        String clientSecret = registerResponse.getClientSecret();

        // 2. Request authorization
        JSONObject jwks = JwtUtil.getJSONWebKeys(jwksUri);

        List<String> scopes = Arrays.asList("openid", "address");
        String nonce = UUID.randomUUID().toString();
        String state = UUID.randomUUID().toString();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(responseTypes, clientId, scopes,
                redirectUri, nonce);
        authorizationRequest.setState(state);

        JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(authorizationRequest,
                KeyEncryptionAlgorithm.PBES2_HS512_PLUS_A256KW, BlockEncryptionAlgorithm.A256CBC_PLUS_HS512,
                clientSecret);
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.AUTHENTICATION_TIME, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addIdTokenClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_STREET_ADDRESS, ClaimValue.createEssential(true)));
        jwtAuthorizationRequest
                .addUserInfoClaim(new Claim(JwtClaimName.ADDRESS_COUNTRY, ClaimValue.createEssential(true)));
        String authJwt = jwtAuthorizationRequest.getEncodedJwt(jwks);
        authorizationRequest.setRequest(authJwt);

        AuthorizeClient authorizeClient = new AuthorizeClient(authorizationEndpoint);
        authorizeClient.setRequest(authorizationRequest);

        AuthorizationResponse authorizationResponse = authenticateResourceOwnerAndGrantAccess(authorizationEndpoint,
                authorizationRequest, userId, userSecret);

        assertNotNull(authorizationResponse.getLocation(), "The location is null");
        assertNotNull(authorizationResponse.getAccessToken(), "The accessToken is null");
        assertNotNull(authorizationResponse.getTokenType(), "The tokenType is null");
        assertNotNull(authorizationResponse.getIdToken(), "The idToken is null");
        assertNotNull(authorizationResponse.getState(), "The state is null");

        String idToken = authorizationResponse.getIdToken();
        String accessToken = authorizationResponse.getAccessToken();

        // 4. Validate id_token
        Jwe jwe = Jwe.parse(idToken, null, null, clientSecret);
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.TYPE));
        assertNotNull(jwe.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUDIENCE));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.EXPIRATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ISSUED_AT));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.AUTHENTICATION_TIME));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsString(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaim(JwtClaimName.ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_LOCALITY));
        assertNotNull(jwe.getClaims().getClaimAsJSON(JwtClaimName.ADDRESS).has(JwtClaimName.ADDRESS_REGION));

        JwtVerifier jweVerifyer = new JwtVerifier(new AuthCryptoProvider(), jwks);
        assertTrue(jweVerifyer.verifyJwt(jwe.getSignedJWTPayload()));

        // 5. Request user info
        UserInfoRequest userInfoRequest = new UserInfoRequest(accessToken);
        UserInfoClient userInfoClient = new UserInfoClient(userInfoEndpoint);
        userInfoClient.setRequest(userInfoRequest);
        userInfoClient.setSharedPassword(clientSecret);
        UserInfoResponse userInfoResponse = userInfoClient.exec();

        showClient(userInfoClient);
        assertEquals(userInfoResponse.getStatus(), 200, "Unexpected response code: " + userInfoResponse.getStatus());
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.SUBJECT_IDENTIFIER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ISSUER));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.AUDIENCE));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_STREET_ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS_COUNTRY));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS));
        assertNotNull(userInfoResponse.getClaim(JwtClaimName.ADDRESS)
                .containsAll(Arrays.asList(JwtClaimName.ADDRESS_STREET_ADDRESS, JwtClaimName.ADDRESS_COUNTRY,
                        JwtClaimName.ADDRESS_LOCALITY, JwtClaimName.ADDRESS_REGION)));
    }

}
