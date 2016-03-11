/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authz.client;

import java.io.IOException;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.HttpHeaders;

/**
 * @author rodrigo.sasaki@icarros.com.br
 */
public class BearerAuthFilter implements ClientRequestFilter {

    private final String tokenString;

    public BearerAuthFilter(String tokenString) {
        this.tokenString = tokenString;
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        String authHeader = "Bearer " + this.tokenString;
        requestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, authHeader);
    }
}
