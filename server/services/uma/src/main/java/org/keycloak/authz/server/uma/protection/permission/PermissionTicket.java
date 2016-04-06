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
package org.keycloak.authz.server.uma.protection.permission;

import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;

import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionTicket extends JsonWebToken {

    private final Set<String> scopes;
    private final String resourceSetId;

    public PermissionTicket() {
        this.scopes = null;
        this.resourceSetId = null;
    }

    public PermissionTicket(String resourceSetId, Set<String> scopes, AccessToken accessToken) {
        this.resourceSetId = resourceSetId;
        this.scopes = scopes;
        id(Identifiers.generateId());
        subject(accessToken.getSubject());
        expiration(accessToken.getExpiration());
        notBefore(accessToken.getNotBefore());
        issuedAt(accessToken.getIssuedAt());
        issuedFor(accessToken.getIssuedFor());
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public String getResourceSetId() {
        return this.resourceSetId;
    }
}
