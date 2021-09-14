/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client.model.authorize;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import io.jans.as.client.AuthorizationRequest;
import io.jans.as.client.util.ClientUtil;
import io.jans.as.model.common.Display;
import io.jans.as.model.common.Prompt;
import io.jans.as.model.common.ResponseType;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.encryption.BlockEncryptionAlgorithm;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.exception.InvalidJwtException;
import io.jans.as.model.jwe.Jwe;
import io.jans.as.model.jwe.JweEncrypterImpl;
import io.jans.as.model.jwk.JWKParameter;
import io.jans.as.model.jwt.JwtClaims;
import io.jans.as.model.jwt.JwtHeader;
import io.jans.as.model.jwt.JwtType;
import io.jans.as.model.util.Base64Util;
import io.jans.as.model.util.Util;

/**
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version September 13, 2021
 */
public class JwtAuthorizationRequest {

    @SuppressWarnings("unused")
    private static final Logger LOG = Logger.getLogger(JwtAuthorizationRequest.class);

    // Header
    private JwtType type;
    private SignatureAlgorithm signatureAlgorithm;
    private KeyEncryptionAlgorithm keyEncryptionAlgorithm;
    private BlockEncryptionAlgorithm blockEncryptionAlgorithm;
    private String keyId;

    // Payload
    private List<ResponseType> responseTypes;
    private String clientId;
    private List<String> scopes;
    private String redirectUri;
    private String state;
    private String nonce;
    private Display display;
    private List<Prompt> prompts;
    private Integer maxAge;
    private List<String> uiLocales;
    private List<String> claimsLocales;
    private String idTokenHint;
    private String loginHint;
    private List<String> acrValues;
    private String registration;
    private boolean requestUniqueId;
    private String aud;
    private Integer exp;
    private String iss;
    private Integer iat;
    private Integer nbf;
    private String jti;
    private String clientNotificationToken;
    private String loginHintToken;
    private String bindingMessage;
    private String userCode;
    private Integer requestedExpiry;

    private UserInfoMember userInfoMember;
    private IdTokenMember idTokenMember;

    // Signature/Encryption Keys
    private String sharedKey;
    private AbstractCryptoProvider cryptoProvider;

    public JwtAuthorizationRequest(AuthorizationRequest authorizationRequest, SignatureAlgorithm signatureAlgorithm,
            AbstractCryptoProvider cryptoProvider) {
        this(authorizationRequest, signatureAlgorithm, cryptoProvider, null, null, null);
    }

    public JwtAuthorizationRequest(AuthorizationRequest authorizationRequest, SignatureAlgorithm signatureAlgorithm,
            String sharedKey, AbstractCryptoProvider cryptoProvider) {
        this(authorizationRequest, signatureAlgorithm, cryptoProvider, null, null, sharedKey);
    }

    public JwtAuthorizationRequest(AuthorizationRequest authorizationRequest,
            KeyEncryptionAlgorithm keyEncryptionAlgorithm, BlockEncryptionAlgorithm blockEncryptionAlgorithm,
            AbstractCryptoProvider cryptoProvider) {
        this(authorizationRequest, null, cryptoProvider, keyEncryptionAlgorithm, blockEncryptionAlgorithm, null);
    }

    public JwtAuthorizationRequest(AuthorizationRequest authorizationRequest,
            KeyEncryptionAlgorithm keyEncryptionAlgorithm, BlockEncryptionAlgorithm blockEncryptionAlgorithm,
            String sharedKey) {
        this(authorizationRequest, null, null, keyEncryptionAlgorithm, blockEncryptionAlgorithm, sharedKey);
    }

    private JwtAuthorizationRequest(AuthorizationRequest authorizationRequest, SignatureAlgorithm signatureAlgorithm,
            AbstractCryptoProvider cryptoProvider, KeyEncryptionAlgorithm keyEncryptionAlgorithm,
            BlockEncryptionAlgorithm blockEncryptionAlgorithm, String sharedKey) {
        setAuthorizationRequestParams(authorizationRequest);

        this.type = JwtType.JWT;
        this.signatureAlgorithm = signatureAlgorithm;
        this.cryptoProvider = cryptoProvider;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.blockEncryptionAlgorithm = blockEncryptionAlgorithm;
        this.sharedKey = sharedKey;

        this.userInfoMember = new UserInfoMember();
        this.idTokenMember = new IdTokenMember();
    }

    private void setAuthorizationRequestParams(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest != null) {
            this.responseTypes = authorizationRequest.getResponseTypes();
            this.clientId = authorizationRequest.getClientId();
            this.scopes = authorizationRequest.getScopes();
            this.redirectUri = authorizationRequest.getRedirectUri();
            this.state = authorizationRequest.getState();
            this.nonce = authorizationRequest.getNonce();
            this.display = authorizationRequest.getDisplay();
            this.prompts = authorizationRequest.getPrompts();
            this.maxAge = authorizationRequest.getMaxAge();
            this.uiLocales = authorizationRequest.getUiLocales();
            this.claimsLocales = authorizationRequest.getClaimsLocales();
            this.idTokenHint = authorizationRequest.getIdTokenHint();
            this.loginHint = authorizationRequest.getLoginHint();
            this.acrValues = authorizationRequest.getAcrValues();
            this.registration = authorizationRequest.getRegistration();
            this.requestUniqueId = authorizationRequest.isRequestSessionId();
        }
    }

    public JwtType getType() {
        return type;
    }

    public void setType(JwtType type) {
        this.type = type;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public KeyEncryptionAlgorithm getKeyEncryptionAlgorithm() {
        return keyEncryptionAlgorithm;
    }

    public void setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm keyEncryptionAlgorithm) {
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    }

    public BlockEncryptionAlgorithm getBlockEncryptionAlgorithm() {
        return blockEncryptionAlgorithm;
    }

    public void setBlockEncryptionAlgorithm(BlockEncryptionAlgorithm blockEncryptionAlgorithm) {
        this.blockEncryptionAlgorithm = blockEncryptionAlgorithm;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public boolean isRequestUniqueId() {
        return requestUniqueId;
    }

    public void setRequestUniqueId(boolean p_requestUniqueId) {
        requestUniqueId = p_requestUniqueId;
    }

    public List<ResponseType> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<ResponseType> responseTypes) {
        this.responseTypes = responseTypes;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public Display getDisplay() {
        return display;
    }

    public void setDisplay(Display display) {
        this.display = display;
    }

    public List<Prompt> getPrompts() {
        return prompts;
    }

    public void setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
    }

    public Integer getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(Integer maxAge) {
        this.maxAge = maxAge;
    }

    public List<String> getUiLocales() {
        return uiLocales;
    }

    public void setUiLocales(List<String> uiLocales) {
        this.uiLocales = uiLocales;
    }

    public List<String> getClaimsLocales() {
        return claimsLocales;
    }

    public void setClaimsLocales(List<String> claimsLocales) {
        this.claimsLocales = claimsLocales;
    }

    public String getIdTokenHint() {
        return idTokenHint;
    }

    public void setIdTokenHint(String idTokenHint) {
        this.idTokenHint = idTokenHint;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public void setLoginHint(String loginHint) {
        this.loginHint = loginHint;
    }

    public List<String> getAcrValues() {
        return acrValues;
    }

    public void setAcrValues(List<String> acrValues) {
        this.acrValues = acrValues;
    }

    public String getRegistration() {
        return registration;
    }

    public void setRegistration(String registration) {
        this.registration = registration;
    }

    public UserInfoMember getUserInfoMember() {
        return userInfoMember;
    }

    public void setUserInfoMember(UserInfoMember userInfoMember) {
        this.userInfoMember = userInfoMember;
    }

    public IdTokenMember getIdTokenMember() {
        return idTokenMember;
    }

    public void setIdTokenMember(IdTokenMember idTokenMember) {
        this.idTokenMember = idTokenMember;
    }

    public void addUserInfoClaim(Claim claim) {
        userInfoMember.getClaims().add(claim);
    }

    public void addIdTokenClaim(Claim claim) {
        idTokenMember.getClaims().add(claim);
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public Integer getExp() {
        return exp;
    }

    public void setExp(Integer exp) {
        this.exp = exp;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public Integer getIat() {
        return iat;
    }

    public void setIat(Integer iat) {
        this.iat = iat;
    }

    public Integer getNbf() {
        return nbf;
    }

    public void setNbf(Integer nbf) {
        this.nbf = nbf;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getClientNotificationToken() {
        return clientNotificationToken;
    }

    public void setClientNotificationToken(String clientNotificationToken) {
        this.clientNotificationToken = clientNotificationToken;
    }

    public String getLoginHintToken() {
        return loginHintToken;
    }

    public void setLoginHintToken(String loginHintToken) {
        this.loginHintToken = loginHintToken;
    }

    public String getBindingMessage() {
        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {
        this.bindingMessage = bindingMessage;
    }

    public String getUserCode() {
        return userCode;
    }

    public void setUserCode(String userCode) {
        this.userCode = userCode;
    }

    public Integer getRequestedExpiry() {
        return requestedExpiry;
    }

    public void setRequestedExpiry(Integer requestedExpiry) {
        this.requestedExpiry = requestedExpiry;
    }

    public String getEncodedJwt(JSONObject jwks) throws Exception {
        String encodedJwt = null;
        if (keyEncryptionAlgorithm != null && blockEncryptionAlgorithm != null) {
            JweEncrypterImpl jweEncrypter = null;
            if (cryptoProvider != null && jwks != null) {
                PublicKey publicKey = cryptoProvider.getPublicKey(keyId, jwks, null);
                if (publicKey instanceof ECPublicKey) {
                    JSONArray webKeys = jwks.getJSONArray(JWKParameter.JSON_WEB_KEY_SET);
                    JSONObject key = null;
                    ECKey ecPublicKey = null;
                    for (int i = 0; i < webKeys.length(); i++) {
                        key = webKeys.getJSONObject(i);
                        if (keyId.equals(key.getString(JWKParameter.KEY_ID))) {
                            ecPublicKey = (ECKey) (JWK.parse(key.toString()));
                            break;
                        }
                    }
                    if (ecPublicKey != null) {
                        jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
                                ecPublicKey);
                    } else {
                        throw new InvalidJwtException("jweEncrypter was not created.");
                    }
                } else {
                    jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, publicKey);
                }
            } else {
                if (keyEncryptionAlgorithm.getFamily() == AlgorithmFamily.PASSW) {
                    jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, sharedKey);
                } else {
                    jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm,
                            sharedKey.getBytes(Util.UTF8_STRING_ENCODING));
                }
            }

            String header = ClientUtil.toPrettyJson(headerToJSONObject());
            String encodedHeader = Base64Util.base64urlencode(header.getBytes(Util.UTF8_STRING_ENCODING));

            String claims = ClientUtil.toPrettyJson(payloadToJSONObject());
            String encodedClaims = Base64Util.base64urlencode(claims.getBytes(Util.UTF8_STRING_ENCODING));

            Jwe jwe = new Jwe();
            jwe.setHeader(new JwtHeader(encodedHeader));
            jwe.setClaims(new JwtClaims(encodedClaims));
            jweEncrypter.encrypt(jwe);

            encodedJwt = jwe.toString();
        } else {
            if (cryptoProvider == null) {
                throw new Exception("The Crypto Provider cannot be null.");
            }

            JSONObject headerJsonObject = headerToJSONObject();
            JSONObject payloadJsonObject = payloadToJSONObject();
            String headerString = ClientUtil.toPrettyJson(headerJsonObject);
            String payloadString = ClientUtil.toPrettyJson(payloadJsonObject);
            String encodedHeader = Base64Util.base64urlencode(headerString.getBytes(Util.UTF8_STRING_ENCODING));
            String encodedPayload = Base64Util.base64urlencode(payloadString.getBytes(Util.UTF8_STRING_ENCODING));
            String signingInput = encodedHeader + "." + encodedPayload;
            String encodedSignature = cryptoProvider.sign(signingInput, keyId, sharedKey, signatureAlgorithm);

            encodedJwt = encodedHeader + "." + encodedPayload + "." + encodedSignature;
        }
        return encodedJwt;
    }

    public String getEncodedJwt() throws Exception {
        return getEncodedJwt(null);
    }

    public String getDecodedJwt() {
        String decodedJwt = null;
        try {
            decodedJwt = ClientUtil.toPrettyJson(payloadToJSONObject());
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return decodedJwt;
    }

    protected JSONObject headerToJSONObject() throws InvalidJwtException {
        JwtHeader jwtHeader = new JwtHeader();

        jwtHeader.setType(type);
        if (keyEncryptionAlgorithm != null && blockEncryptionAlgorithm != null) {
            jwtHeader.setAlgorithm(keyEncryptionAlgorithm);
            jwtHeader.setEncryptionMethod(blockEncryptionAlgorithm);
        } else {
            jwtHeader.setAlgorithm(signatureAlgorithm);
        }
        jwtHeader.setKeyId(keyId);

        return jwtHeader.toJsonObject();
    }

    protected JSONObject payloadToJSONObject() throws JSONException {
        JSONObject obj = new JSONObject();

        try {
            if (responseTypes != null && !responseTypes.isEmpty()) {
                if (responseTypes.size() == 1) {
                    ResponseType responseType = responseTypes.get(0);
                    obj.put("response_type", responseType);
                } else {
                    JSONArray responseTypeJsonArray = new JSONArray();
                    for (ResponseType responseType : responseTypes) {
                        responseTypeJsonArray.put(responseType);
                    }
                    obj.put("response_type", responseTypeJsonArray);
                }
            }
            if (StringUtils.isNotBlank(clientId)) {
                obj.put("client_id", clientId);
            }
            if (scopes != null && !scopes.isEmpty()) {
                if (scopes.size() == 1) {
                    String scope = scopes.get(0);
                    obj.put("scope", scope);
                } else {
                    JSONArray scopeJsonArray = new JSONArray();
                    for (String scope : scopes) {
                        scopeJsonArray.put(scope);
                    }
                    obj.put("scope", scopeJsonArray);
                }
            }
            if (StringUtils.isNotBlank(redirectUri)) {
                obj.put("redirect_uri", URLEncoder.encode(redirectUri, "UTF-8"));
            }
            if (StringUtils.isNotBlank(state)) {
                obj.put("state", state);
            }
            if (StringUtils.isNotBlank(nonce)) {
                obj.put("nonce", nonce);
            }
            if (display != null) {
                obj.put("display", display);
            }
            if (prompts != null && !prompts.isEmpty()) {
                JSONArray promptJsonArray = new JSONArray();
                for (Prompt prompt : prompts) {
                    promptJsonArray.put(prompt);
                }
                obj.put("prompt", promptJsonArray);
            }
            if (maxAge != null) {
                obj.put("max_age", maxAge);
            }
            if (uiLocales != null && !uiLocales.isEmpty()) {
                JSONArray uiLocalesJsonArray = new JSONArray(uiLocales);
                obj.put("ui_locales", uiLocalesJsonArray);
            }
            if (claimsLocales != null && !claimsLocales.isEmpty()) {
                JSONArray claimsLocalesJsonArray = new JSONArray(claimsLocales);
                obj.put("claims_locales", claimsLocalesJsonArray);
            }
            if (StringUtils.isNotBlank(idTokenHint)) {
                obj.put("id_token_hint", idTokenHint);
            }
            if (StringUtils.isNotBlank(loginHint)) {
                obj.put("login_hint", loginHint);
            }
            if (acrValues != null && !acrValues.isEmpty()) {
                JSONArray acrValuesJsonArray = new JSONArray(acrValues);
                obj.put("acr_values", acrValues);
            }
            if (StringUtils.isNotBlank(registration)) {
                obj.put("registration", registration);
            }

            if (userInfoMember != null || idTokenMember != null) {
                JSONObject claimsObj = new JSONObject();

                if (userInfoMember != null) {
                    claimsObj.put("userinfo", userInfoMember.toJSONObject());
                }
                if (idTokenMember != null) {
                    claimsObj.put("id_token", idTokenMember.toJSONObject());
                }

                obj.put("claims", claimsObj);
            }
            if (StringUtils.isNotBlank(aud)) {
                obj.put("aud", aud);
            }
            if (exp != null && exp > 0) {
                obj.put("exp", exp);
            }
            if (StringUtils.isNotBlank(iss)) {
                obj.put("iss", iss);
            }
            if (iat != null && iat > 0) {
                obj.put("iat", iat);
            }
            if (nbf != null && nbf > 0) {
                obj.put("nbf", nbf);
            }
            if (StringUtils.isNotBlank(jti)) {
                obj.put("jti", jti);
            }
            if (StringUtils.isNotBlank(clientNotificationToken)) {
                obj.put("client_notification_token", clientNotificationToken);
            }
            if (StringUtils.isNotBlank(loginHintToken)) {
                obj.put("login_hint_token", loginHintToken);
            }
            if (StringUtils.isNotBlank(bindingMessage)) {
                obj.put("binding_message", bindingMessage);
            }
            if (StringUtils.isNotBlank(userCode)) {
                obj.put("user_code", userCode);
            }
            if (requestedExpiry != null && requestedExpiry > 0) {
                obj.put("requested_expirity", requestedExpiry);
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return obj;
    }

}