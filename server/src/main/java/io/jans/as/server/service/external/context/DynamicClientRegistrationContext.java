/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.service.external.context;

import io.jans.as.client.RegisterRequest;
import io.jans.as.common.model.registration.Client;
import io.jans.as.model.error.ErrorResponseFactory;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.register.RegisterErrorResponseType;
import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.conf.CustomScriptConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Yuriy Zabrovarnyy
 */
public class DynamicClientRegistrationContext extends ExternalScriptContext {

    private static final Logger log = LoggerFactory.getLogger(DynamicClientRegistrationContext.class);

    private CustomScriptConfiguration script;
    private JSONObject registerRequestJson;
    private RegisterRequest registerRequest;
    private Jwt softwareStatement;
    private Jwt dcr;
    private Client client;
    private ErrorResponseFactory errorResponseFactory;

    public DynamicClientRegistrationContext(HttpServletRequest httpRequest, JSONObject registerRequest, CustomScriptConfiguration script) {
        this(httpRequest, registerRequest, script, null);
    }

    public DynamicClientRegistrationContext(HttpServletRequest httpRequest, JSONObject registerRequest, CustomScriptConfiguration script, Client client) {
        super(httpRequest);
        this.script = script;
        this.registerRequestJson = registerRequest;
        this.client = client;
    }

    public Jwt getDcr() {
        return dcr;
    }

    public void setDcr(Jwt dcr) {
        this.dcr = dcr;
    }

    public Jwt getSoftwareStatement() {
        return softwareStatement;
    }

    public void setSoftwareStatement(Jwt softwareStatement) {
        this.softwareStatement = softwareStatement;
    }

    public CustomScriptConfiguration getScript() {
        return script;
    }

    public void setScript(CustomScriptConfiguration script) {
        this.script = script;
    }

    public JSONObject getRegisterRequestJson() {
        return registerRequestJson;
    }

    public void setRegisterRequestJson(JSONObject registerRequestJson) {
        this.registerRequestJson = registerRequestJson;
    }

    public RegisterRequest getRegisterRequest() {
        return registerRequest;
    }

    public void setRegisterRequest(RegisterRequest registerRequest) {
        this.registerRequest = registerRequest;
    }

    public Map<String, SimpleCustomProperty> getConfigurationAttibutes() {
        final Map<String, SimpleCustomProperty> attrs = script.getConfigurationAttributes();

        if (httpRequest != null) {
            final String cert = httpRequest.getHeader("X-ClientCert");
            if (StringUtils.isNotBlank(cert)) {
                SimpleCustomProperty certProperty = new SimpleCustomProperty();
                certProperty.setValue1(cert);
                attrs.put("certProperty", certProperty);
            }
        }
        return attrs != null ? new HashMap<>(attrs) : new HashMap<>();
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public void validateSSA() {
        validateSSANotNull();
        validateSSARedirectUri();
    }

    public void validateSSARedirectUri() {
        validateSSARedirectUri("software_redirect_uris");
    }

    public void validateSSARedirectUri(String ssaRedirectUriClaimName) {
        if (!softwareStatement.getClaims().hasClaim(ssaRedirectUriClaimName))
            return; // skip validation, redirect_uris are not set in SSA

        final List<String> ssaRedirectUris = softwareStatement.getClaims().getClaimAsStringList(ssaRedirectUriClaimName);
        final List<String> redirectUris = registerRequest.getRedirectUris();
        if (ssaRedirectUris.containsAll(redirectUris))
            return;

        log.error("SSA redirect_uris does not match redirect_uris of the request. SSA redirect_uris: " + ssaRedirectUris + ", request redirectUris: " + redirectUris);
        throwWebApplicationExceptionIfSet();
        throw createWebApplicationException(Response.Status.BAD_REQUEST.getStatusCode(), errorResponseFactory.getErrorAsJson(RegisterErrorResponseType.INVALID_REDIRECT_URI));
    }

    public void validateSSANotNull() {
        if (softwareStatement == null) {
            log.error("SSA is null");
            throwWebApplicationExceptionIfSet();
            throw createWebApplicationException(Response.Status.BAD_REQUEST.getStatusCode(), errorResponseFactory.getErrorAsJson(RegisterErrorResponseType.INVALID_SOFTWARE_STATEMENT));
        }
    }

    public ErrorResponseFactory getErrorResponseFactory() {
        return errorResponseFactory;
    }

    public void setErrorResponseFactory(ErrorResponseFactory errorResponseFactory) {
        this.errorResponseFactory = errorResponseFactory;
    }

    @Override
    public String toString() {
        return "DynamicClientRegistrationContext{" +
                "softwareStatement=" + softwareStatement +
                "registerRequest=" + registerRequestJson +
                "script=" + script +
                "} " + super.toString();
    }
}
