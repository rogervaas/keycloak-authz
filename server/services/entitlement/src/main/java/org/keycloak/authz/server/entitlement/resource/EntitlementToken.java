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
package org.keycloak.authz.server.entitlement.resource;

import java.util.List;
import org.keycloak.representations.JsonWebToken;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EntitlementToken extends JsonWebToken {

    private final List<EntitledResource> permissions;

    public EntitlementToken() {
        this(null);
    }

    public EntitlementToken(List<EntitledResource> permissions) {
        this.permissions = permissions;
        type("kc_ett");
    }

    public List<EntitledResource> getPermissions() {
        return this.permissions;
    }
}
