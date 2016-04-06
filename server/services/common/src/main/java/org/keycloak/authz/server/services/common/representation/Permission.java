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
package org.keycloak.authz.server.services.common.representation;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Permission {

    @JsonProperty("resource_set_id")
    private String resourceSetId;

    @JsonProperty("resource_set_name")
    private String resourceName;

    private List<String> scopes;

    public Permission() {
        this(null, null);
    }

    public Permission(final String resourceSetId, final List<String> scopes) {
        this.resourceSetId = resourceSetId;
        this.scopes = scopes;
    }

    public String getResourceSetId() {
        return this.resourceSetId;
    }

    private String getResourceName() {
        return this.resourceName;
    }

    public List<String> getScopes() {
        return this.scopes;
    }
}