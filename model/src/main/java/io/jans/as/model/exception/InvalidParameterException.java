/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.exception;

/**
 * @author Javier Rojas Blum Date: 10.22.2012
 */
public class InvalidParameterException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = 5104056185118314221L;

    public InvalidParameterException(String message) {
        super(message);
    }

    public InvalidParameterException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidParameterException(Throwable cause) {
        super(cause);
    }
}