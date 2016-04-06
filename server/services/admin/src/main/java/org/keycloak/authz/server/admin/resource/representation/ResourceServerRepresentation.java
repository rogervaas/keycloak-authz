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
package org.keycloak.authz.server.admin.resource.representation;

import org.keycloak.authz.core.model.ResourceServer;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceServerRepresentation {

    private String id;

    private String clientId;
    private String name;
    private boolean allowRemoteResourceManagement;
    private boolean allowEntitlements;
    private ResourceServer.PolicyEnforcementMode policyEnforcementMode;
    private List<ResourceRepresentation> resources;
    private List<PolicyRepresentation> policies;
    private List<ScopeRepresentation> scopes;

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isAllowRemoteResourceManagement() {
        return this.allowRemoteResourceManagement;
    }

    public void setAllowRemoteResourceManagement(boolean allowRemoteResourceManagement) {
        this.allowRemoteResourceManagement = allowRemoteResourceManagement;
    }

    public boolean isAllowEntitlements() {
        return this.allowEntitlements;
    }

    public void setAllowEntitlements(boolean allowEntitlements) {
        this.allowEntitlements = allowEntitlements;
    }

    public ResourceServer.PolicyEnforcementMode getPolicyEnforcementMode() {
        return this.policyEnforcementMode;
    }

    public void setPolicyEnforcementMode(ResourceServer.PolicyEnforcementMode policyEnforcementMode) {
        this.policyEnforcementMode = policyEnforcementMode;
    }

    public void setResources(List<ResourceRepresentation> resources) {
        this.resources = resources;
    }

    public List<ResourceRepresentation> getResources() {
        return resources;
    }

    public void setPolicies(List<PolicyRepresentation> policies) {
        this.policies = policies;
    }

    public List<PolicyRepresentation> getPolicies() {
        return policies;
    }

    public void setScopes(List<ScopeRepresentation> scopes) {
        this.scopes = scopes;
    }

    public List<ScopeRepresentation> getScopes() {
        return scopes;
    }
}
