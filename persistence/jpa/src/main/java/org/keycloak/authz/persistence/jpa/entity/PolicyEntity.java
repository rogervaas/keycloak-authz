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

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.Scope;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.MapKeyColumn;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Entity
@Table(uniqueConstraints = {
        @UniqueConstraint(columnNames = {"name", "resourceServerId"})
})
public class PolicyEntity implements Policy {

    @Id
    private String id;

    @Column(name = "name")
    private String name;

    @Column
    private String description;

    @Column
    private String type;

    @Column
    private DecisionStrategy decisionStrategy = DecisionStrategy.UNANIMOUS;

    @Column
    private Logic logic = Logic.POSITIVE;

    @ElementCollection(fetch = FetchType.EAGER)
    @MapKeyColumn(name="NAME")
    @Column(name="VALUE", columnDefinition = "TEXT")
    @CollectionTable
    private Map<String, String> config = new HashMap();

    @ManyToOne(optional = false)
    @JoinColumn(name = "resourceServerId")
    private ResourceServerEntity resourceServer;

    @ManyToMany(fetch = FetchType.EAGER, cascade = {})
    private Set<PolicyEntity> associatedPolicies = new HashSet<>();

    @ManyToMany(fetch = FetchType.EAGER, cascade = {})
    private Set<ResourceEntity> resources = new HashSet<>();

    @ManyToMany(fetch = FetchType.EAGER, cascade = {})
    private Set<ScopeEntity> scopes = new HashSet<>();

    @Override
    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @Override
    public DecisionStrategy getDecisionStrategy() {
        return this.decisionStrategy;
    }

    @Override
    public void setDecisionStrategy(DecisionStrategy decisionStrategy) {
        this.decisionStrategy = decisionStrategy;
    }

    @Override
    public Logic getLogic() {
        return this.logic;
    }

    @Override
    public void setLogic(Logic logic) {
        this.logic = logic;
    }

    @Override
    public Map<String, String> getConfig() {
        return this.config;
    }

    @Override
    public void setConfig(Map<String, String> config) {
        this.config = config;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public ResourceServerEntity getResourceServer() {
        return this.resourceServer;
    }

    public void setResourceServer(ResourceServerEntity resourceServer) {
        this.resourceServer = resourceServer;
    }

    @Override
    public Set<Policy> getAssociatedPolicies() {
        return this.associatedPolicies.stream().map(entity -> entity).collect(Collectors.toSet());
    }

    public void setAssociatedPolicies(Set<PolicyEntity> associatedPolicies) {
        this.associatedPolicies = associatedPolicies;
    }

    @Override
    public void addAssociatedPolicy(Policy policy) {
        this.associatedPolicies.add((PolicyEntity) policy);
    }

    @Override
    public void removeAssociatedPolicy(Policy policy) {
        this.associatedPolicies.remove(policy);
    }

    @Override
    public Set<Resource> getResources() {
        return this.resources.stream().map(entity -> entity).collect(Collectors.toSet());
    }

    public void setResources(Set<ResourceEntity> resources) {
        this.resources = resources;
    }

    @Override
    public void addResource(Resource resource) {
        this.resources.add((ResourceEntity) resource);
    }

    @Override
    public void removeResource(Resource resource) {
        this.resources.remove(resource);
    }

    @Override
    public Set<Scope> getScopes() {
        return this.scopes.stream().map(entity -> entity).collect(Collectors.toSet());
    }

    @Override
    public void addScope(Scope scope) {
        this.scopes.add((ScopeEntity) scope);
    }

    public void setScopes(Set<ScopeEntity> scopes) {
        this.scopes = scopes;
    }

    @Override
    public void removeScope(Scope scope) {
        this.scopes.remove(scope);
    }
}
