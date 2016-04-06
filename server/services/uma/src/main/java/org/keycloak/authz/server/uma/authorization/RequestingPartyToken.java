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
package org.keycloak.authz.server.uma.authorization;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RequestingPartyToken extends JsonWebToken {

    private final List<Permission> permissions;
    private final String accessToken;

    public RequestingPartyToken() {
        this.permissions = null;
        this.accessToken = null;
    }

    public RequestingPartyToken(AccessToken accessToken, String accessTokenString, Permission... permissions) {
        if (permissions != null) {
            this.permissions = new ArrayList<>(Arrays.asList(permissions));
        } else {
            this.permissions = null;
        }

        this.accessToken = accessTokenString;

        type("rpt");

        id(Identifiers.generateId());
        subject(accessToken.getSubject());
        expiration(accessToken.getExpiration());
        notBefore(accessToken.getNotBefore());
        issuedAt(accessToken.getIssuedAt());
        issuedFor(accessToken.getIssuedFor());
    }

    public List<Permission> getPermissions() {
        return this.permissions;
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    @JsonIgnore
    public boolean isValid() {
        return getType() != null && getType().equals("rpt") &&  isActive();
    }
}
