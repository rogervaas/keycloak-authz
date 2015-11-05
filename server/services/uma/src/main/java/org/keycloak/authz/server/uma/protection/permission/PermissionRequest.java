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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionRequest {

    @JsonProperty("resource_set_id")
    private final String resourceSetId;

    private final Set<String> scopes;

    public PermissionRequest(String resourceSetId, String... scopes) {
        this.resourceSetId = resourceSetId;

        if (scopes != null) {
            this.scopes = new HashSet(Arrays.asList(scopes));
        } else {
            this.scopes = new HashSet<>();
        }
    }

    public PermissionRequest() {
        this(null, null);
    }

    public String getResourceSetId() {
        return this.resourceSetId;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
