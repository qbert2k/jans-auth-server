/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang.StringUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.common.AuthorizationMethod;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.exception.InvalidJweException;
import io.jans.as.model.jwe.Jwe;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.userinfo.UserInfoErrorResponseType;
import io.jans.as.model.util.JwtUtil;

/**
 * Encapsulates functionality to make user info request calls to an
 * authorization server via REST Services.
 *
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public class UserInfoClient extends BaseClient<UserInfoRequest, UserInfoResponse> {
    
    public static final String DEF_ERROR = "error";
    public static final String DEF_ERROR_DESCRIPTION = "error_description";
    public static final String DEF_ERROR_URI = "error_uri";    

    private String jwksUri;

    private PrivateKey privateKey = null;
    private byte[] sharedKey = null;
    private String sharedPassword = null;

    /**
     * Constructs an User Info client by providing a REST url where the service is
     * located.
     *
     * @param url The REST Service location.
     */
    public UserInfoClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {
        if (request.getAuthorizationMethod() == null
                || request.getAuthorizationMethod() == AuthorizationMethod.AUTHORIZATION_REQUEST_HEADER_FIELD
                || request.getAuthorizationMethod() == AuthorizationMethod.URL_QUERY_PARAMETER) {
            return HttpMethod.GET;
        } else {
            return HttpMethod.POST;
        }
    }

    /**
     * Executes the call to the REST Service and processes the response.
     *
     * @param accessToken The access token obtained from the Jans Auth authorization
     *                    request.
     * @return The service response.
     */
    public UserInfoResponse execUserInfo(String accessToken) {
        setRequest(new UserInfoRequest(accessToken));

        return exec();
    }

    /**
     * Executes the call to the REST Service and processes the response.
     *
     * @return The service response.
     */
    public UserInfoResponse exec() {
        // Prepare request parameters
        initClientRequest();
        clientRequest.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);
        clientRequest.setHttpMethod(getHttpMethod());

        if (getRequest().getAuthorizationMethod() == null
                || getRequest().getAuthorizationMethod() == AuthorizationMethod.AUTHORIZATION_REQUEST_HEADER_FIELD) {
            if (StringUtils.isNotBlank(getRequest().getAccessToken())) {
                clientRequest.header("Authorization", "Bearer " + getRequest().getAccessToken());
            }
        } else if (getRequest().getAuthorizationMethod() == AuthorizationMethod.FORM_ENCODED_BODY_PARAMETER) {
            if (StringUtils.isNotBlank(getRequest().getAccessToken())) {
                clientRequest.formParameter("access_token", getRequest().getAccessToken());
            }
        } else if (getRequest().getAuthorizationMethod() == AuthorizationMethod.URL_QUERY_PARAMETER) {
            if (StringUtils.isNotBlank(getRequest().getAccessToken())) {
                clientRequest.queryParameter("access_token", getRequest().getAccessToken());
            }
        }

        // Call REST Service and handle response
        try {
            if (getRequest().getAuthorizationMethod() == null
                    || getRequest().getAuthorizationMethod() == AuthorizationMethod.AUTHORIZATION_REQUEST_HEADER_FIELD
                    || getRequest().getAuthorizationMethod() == AuthorizationMethod.URL_QUERY_PARAMETER) {
                clientResponse = clientRequest.get(String.class);
            } else if (getRequest().getAuthorizationMethod() == AuthorizationMethod.FORM_ENCODED_BODY_PARAMETER) {
                clientResponse = clientRequest.post(String.class);
            }

            int status = clientResponse.getStatus();

            setResponse(new UserInfoResponse(status));

            String entity = clientResponse.getEntity(String.class);
            getResponse().setEntity(entity);
            getResponse().setHeaders(clientResponse.getMetadata());
            if (StringUtils.isNotBlank(entity)) {
                List<Object> contentType = clientResponse.getHeaders().get("Content-Type");
                if (contentType != null && contentType.contains("application/jwt")) {
                    String[] jwtParts = entity.split("\\.");
                    if (jwtParts.length == 5) {
                        Jwe jwe = null;
                        if (privateKey != null) {
                            jwe = Jwe.parse(entity, privateKey);
                        } else if (sharedKey != null) {
                            jwe = Jwe.parse(entity, null, sharedKey, null);
                        } else if (sharedPassword != null) {
                            jwe = Jwe.parse(entity, null, null, sharedPassword);
                        } else {
                            throw new InvalidJweException(
                                    "privateKey, sharedKey, sharedPassword: keys aren't defined, jwe object hasn't been encrypted");
                        }
                        getResponse().setClaims(jwe.getClaims().toMap());
                    } else {
                        Jwt jwt = Jwt.parse(entity);
                        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider();
                        boolean signatureVerified = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(),
                                jwt.getHeader().getKeyId(), JwtUtil.getJSONWebKeys(jwksUri),
                                (sharedKey != null) ? new String(sharedKey) : null, jwt.getHeader().getSignatureAlgorithm());

                        if (signatureVerified) {
                            getResponse().setClaims(jwt.getClaims().toMap());
                        }
                    }
                } else {
                    try {
                        JSONObject jsonObj = new JSONObject(entity);

                        if (jsonObj.has(DEF_ERROR)) {
                            getResponse().setErrorType(UserInfoErrorResponseType.fromString(jsonObj.getString(DEF_ERROR)));
                            jsonObj.remove(DEF_ERROR);
                        }
                        if (jsonObj.has(DEF_ERROR_DESCRIPTION)) {
                            getResponse().setErrorDescription(jsonObj.getString(DEF_ERROR_DESCRIPTION));
                            jsonObj.remove(DEF_ERROR_DESCRIPTION);
                        }
                        if (jsonObj.has(DEF_ERROR_URI)) {
                            getResponse().setErrorUri(jsonObj.getString(DEF_ERROR_URI));
                            jsonObj.remove(DEF_ERROR_URI);
                        }

                        for (Iterator<String> iterator = jsonObj.keys(); iterator.hasNext();) {
                            String key = iterator.next();
                            List<String> values = new ArrayList<String>();

                            JSONArray jsonArray = jsonObj.optJSONArray(key);
                            if (jsonArray != null) {
                                for (int i = 0; i < jsonArray.length(); i++) {
                                    String value = jsonArray.optString(i);
                                    if (value != null) {
                                        values.add(value);
                                    }
                                }
                            } else {
                                String value = jsonObj.optString(key);
                                if (value != null) {
                                    values.add(value);
                                }
                            }

                            getResponse().getClaims().put(key, values);
                        }
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            closeConnection();
        }

        return getResponse();
    }

    public void setSharedKey(byte[] sharedKey) {
        this.sharedKey = sharedKey;
    }

    public void setSharedPassword(String sharedPassword) {
        this.sharedPassword = sharedPassword;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }
}