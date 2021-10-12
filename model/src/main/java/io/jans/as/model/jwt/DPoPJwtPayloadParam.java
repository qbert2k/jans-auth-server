/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */
package io.jans.as.model.jwt;

/**
 * @author Javier Rojas Blum
 * @version September 30, 2021
 */
public interface DPoPJwtPayloadParam {

    /**
     * Unique identifier for the DPoP proof JWT.
     * The value must be assigned such that there is a negligible probability that the same value will be assigned
     * to any other DPoP proof used in the same context during the time window of validity.
     */
    String JTI = "jti";

    /**
     * The HTTP method for the request to which the JWT is attached.
     */
    String HTM = "htm";

    /**
     * The HTTP URI used for the request, without query and fragment parts.
     */
    String HTU = "htu";

    /**
     * Time at which the JWT was created.
     */
    String IAT = "iat";

    /**
     * Hash of the access token. Required when the DPoP proof is used in conjunction with the presentation of an
     * access token.
     */
    String ATH = "ath";
}
