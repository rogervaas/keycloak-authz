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
package org.keycloak.authz.persistence.jpa.entity;

import org.keycloak.authz.core.model.ResourceServer;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Entity
public class ResourceServerEntity implements ResourceServer {

    @Id
    private String id;

    @Column (unique = true)
    private String clientId;

    @Column
    private boolean allowRemoteResourceManagement;

    @Column
    private boolean allowEntitlements;

    @Column
    private PolicyEnforcementMode policyEnforcementMode;

    @OneToMany (mappedBy = "resourceServer")
    private List<ResourceEntity> resources;

    @OneToMany (mappedBy = "resourceServer")
    private List<ScopeEntity> scopes;

    @Override
    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getClientId() {
        return this.clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public boolean isAllowRemoteResourceManagement() {
        return this.allowRemoteResourceManagement;
    }

    @Override
    public void setAllowRemoteResourceManagement(boolean allowRemoteResourceManagement) {
        this.allowRemoteResourceManagement = allowRemoteResourceManagement;
    }

    @Override
    public boolean isAllowEntitlements() {
        return this.allowEntitlements;
    }

    @Override
    public void setAllowEntitlements(boolean allowEntitlements) {
        this.allowEntitlements = allowEntitlements;
    }

    @Override
    public PolicyEnforcementMode getPolicyEnforcementMode() {
        return this.policyEnforcementMode;
    }

    @Override
    public void setPolicyEnforcementMode(PolicyEnforcementMode policyEnforcementMode) {
        this.policyEnforcementMode = policyEnforcementMode;
    }

    public List<ResourceEntity> getResources() {
        return this.resources;
    }

    public void setResources(final List<ResourceEntity> resources) {
        this.resources = resources;
    }

    public List<ScopeEntity> getScopes() {
        return this.scopes;
    }

    public void setScopes(final List<ScopeEntity> scopes) {
        this.scopes = scopes;
    }
}
