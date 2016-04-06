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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.keycloak.authz.core.model.Policy;
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

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Entity
@Table(uniqueConstraints = {
        @UniqueConstraint(columnNames = {"name", "resourceServerId"})
})
public class ScopeEntity implements Scope {

    @Id
    private String id;

    @Column (unique = true)
    private String name;

    @Column
    private String iconUri;

    @ManyToOne(optional = false)
    @JoinColumn(name = "resourceServerId")
    private ResourceServerEntity resourceServer;

    @ManyToMany(mappedBy = "scopes", fetch = FetchType.EAGER)
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

    @Override
    public List<? extends Policy> getPolicies() {
        return this.policies;
    }

    public void setPolicies(List<PolicyEntity> policies) {
        this.policies = policies;
    }

    public void setResourceServer(final ResourceServerEntity resourceServer) {
        this.resourceServer = resourceServer;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScopeEntity that = (ScopeEntity) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
