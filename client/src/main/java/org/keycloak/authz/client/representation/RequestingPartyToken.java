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
package org.keycloak.authz.client.representation;

import org.keycloak.representations.JsonWebToken;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RequestingPartyToken extends JsonWebToken {

    private final List<Permission> permissions;
    private String accessToken;

    public RequestingPartyToken() {
        this.permissions = null;
    }

    public List<Permission> getPermissions() {
        return this.permissions;
    }

    public String getAccessToken() {
        return this.accessToken;
    }

    public boolean isValid(String... types) {
        return isOfType(types) &&  isActive();
    }

    private boolean isOfType(String[] types) {
        if (getType() == null) {
            return false;
        }

        if (types.length == 0) {
            types = new String[] {"rpt", "kc_ett"};
        }

        boolean validType = false;

        for (String type : types) {
            if (getType().equals(type)) {
                validType = true;
                break;
            }
        }
        return validType;
    }
}
