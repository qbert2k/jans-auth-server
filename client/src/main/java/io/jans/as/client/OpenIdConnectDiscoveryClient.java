/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client;

import static io.jans.as.model.discovery.WebFingerParam.HREF;
import static io.jans.as.model.discovery.WebFingerParam.LINKS;
import static io.jans.as.model.discovery.WebFingerParam.REL;
import static io.jans.as.model.discovery.WebFingerParam.REL_VALUE;
import static io.jans.as.model.discovery.WebFingerParam.RESOURCE;
import static io.jans.as.model.discovery.WebFingerParam.SUBJECT;

import java.net.URISyntaxException;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import io.jans.as.model.discovery.WebFingerLink;

/**
 * @author Javier Rojas Blum
 * @version December 26, 2016
 */
public class OpenIdConnectDiscoveryClient extends BaseClient<OpenIdConnectDiscoveryRequest, OpenIdConnectDiscoveryResponse> {

    private static final Logger LOG = Logger.getLogger(OpenIdConnectDiscoveryClient.class);

    private static final String MEDIA_TYPE = MediaType.APPLICATION_JSON;
    private static final String SCHEMA = "https://";
    private static final String PATH = "/.well-known/webfinger";

    public OpenIdConnectDiscoveryClient(String resource) throws URISyntaxException {
        setRequest(new OpenIdConnectDiscoveryRequest(resource));
        setUrl(SCHEMA + getRequest().getHost() + PATH);
    }

    @Override
    public String getHttpMethod() {
        return HttpMethod.GET;
    }

    public OpenIdConnectDiscoveryResponse exec() {
        initClientRequest();

        return _exec();
    }

    @Deprecated
    public OpenIdConnectDiscoveryResponse exec(ClientExecutor executor) {
        this.clientRequest = new ClientRequest(getUrl(), executor);
        return _exec();
    }

    private OpenIdConnectDiscoveryResponse _exec() {
        OpenIdConnectDiscoveryResponse response = null;

        try {
            response = _exec2();
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        } finally {
            closeConnection();
        }

        return response;
    }

    private OpenIdConnectDiscoveryResponse _exec2() {
        // Prepare request parameters
        clientRequest.accept(MEDIA_TYPE);
        clientRequest.setHttpMethod(getHttpMethod());

        if (StringUtils.isNotBlank(getRequest().getResource())) {
            clientRequest.queryParameter(RESOURCE, getRequest().getResource());
        }
        clientRequest.queryParameter(REL, REL_VALUE);

        // Call REST Service and handle response
        ClientResponse<String> clientResponse1;
        try {
            clientResponse1 = clientRequest.get(String.class);
            int status = clientResponse1.getStatus();

            setResponse(new OpenIdConnectDiscoveryResponse(status));

            String entity = clientResponse1.getEntity(String.class);
            getResponse().setEntity(entity);
            getResponse().setHeaders(clientResponse1.getMetadata());
            if (StringUtils.isNotBlank(entity)) {
                JSONObject jsonObj = new JSONObject(entity);
                getResponse().setSubject(jsonObj.getString(SUBJECT));
                JSONArray linksJsonArray = jsonObj.getJSONArray(LINKS);
                for (int i = 0; i < linksJsonArray.length(); i++) {
                    WebFingerLink webFingerLink = new WebFingerLink();
                    webFingerLink.setRel(linksJsonArray.getJSONObject(i).getString(REL));
                    webFingerLink.setHref(linksJsonArray.getJSONObject(i).getString(HREF));

                    getResponse().getLinks().add(webFingerLink);
                }
            }
        } catch (JSONException e) {
            LOG.error(e.getMessage(), e);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }

        return getResponse();
    }
}