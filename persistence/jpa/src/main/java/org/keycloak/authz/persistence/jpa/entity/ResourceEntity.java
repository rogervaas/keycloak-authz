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

import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.Scope;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Entity
@Table(uniqueConstraints = {
        @UniqueConstraint(columnNames = {"name", "resourceServerId"})
})
public class ResourceEntity implements Resource {

    @Id
    @Column(unique = true)
    private String id;

    @Column(name = "name")
    private String name;

    @Column
    private String uri;

    @Column
    private String type;

    @ManyToMany(fetch = FetchType.EAGER, cascade = {})
    private List<ScopeEntity> scopes = new ArrayList<>();

    @Column
    private String iconUri;

    @Column
    private String owner;

    @ManyToOne(optional = false)
    @JoinColumn(name = "resourceServerId")
    private ResourceServerEntity resourceServer;

    @ManyToMany(mappedBy = "resources", fetch = FetchType.EAGER)
    private List<PolicyEntity> policies = new ArrayList<>();

    @Override
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getUri() {
        return uri;
    }

    @Override
    public void setUri(String uri) {
        this.uri = uri;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public void setType(String type) {
        this.type = type;
    }

    @Override
    public List<Scope> getScopes() {
        return this.scopes.stream().map(entity -> entity).collect(Collectors.toList());
    }

    @Override
    public String getIconUri() {
        return iconUri;
    }

    @Override
    public void setIconUri(String iconUri) {
        this.iconUri = iconUri;
    }

    @Override
    public ResourceServerEntity getResourceServer() {
        return resourceServer;
    }

    public void setResourceServer(ResourceServerEntity resourceServer) {
        this.resourceServer = resourceServer;
    }

    public String getOwner() {
        return this.owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public List<PolicyEntity> getPolicies() {
        return this.policies;
    }

    @Override
    public void addScope(Scope scope) {
        this.scopes.add((ScopeEntity) scope);
    }

    @Override
    public void removeScope(Scope scope) {
        this.scopes.remove(scope);
    }

    @Override
    public void updateScopes(Set<Scope> toUpdate) {
        for (Scope scope : toUpdate) {
            boolean hasScope = false;

            for (Scope existingScope : this.scopes) {
                if (existingScope.equals(scope)) {
                    hasScope = true;
                }
            }

            if (!hasScope) {
                addScope(scope);
            }
        }

        for (Scope scopeModel : new HashSet<Scope>(this.scopes)) {
            boolean hasScope = false;

            for (Scope scope : toUpdate) {
                if (scopeModel.equals(scope)) {
                    hasScope = true;
                }
            }

            if (!hasScope) {
                removeScope(scopeModel);
            }
        }
    }

    public void setPolicies(List<PolicyEntity> policies) {
        this.policies = policies;
    }
}
