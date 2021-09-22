/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.model.util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * @author Yuriy Zabrovarnyy
 */
public class QueryBuilder {

    private static final Logger LOG = Logger.getLogger(QueryBuilder.class);

    private final StringBuilder builder;

    public QueryBuilder() {
        this(new StringBuilder());
    }

    public QueryBuilder(StringBuilder builder) {
        this.builder = builder;
    }

    public static QueryBuilder instance() {
        return new QueryBuilder();
    }

    public String build() {
        return builder.toString();
    }

    public StringBuilder getBuilder() {
        return builder;
    }

    public void appendIfNotNull(String key, Object value) {
        if (value != null) {
            append(key, value.toString());
        }
    }

    public void append(String key, String value) {
        if (StringUtils.isNotBlank(value)) {
            if (builder.length() > 0) {
                appendAmpersand();
            }
            builder.append(key).append("=").append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
    }

    public void appendAmpersand() {
        builder.append("&");
    }

    @Override
    public String toString() {
        return build();
    }
}

