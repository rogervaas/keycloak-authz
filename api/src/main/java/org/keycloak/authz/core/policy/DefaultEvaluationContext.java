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
package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.Identity;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.models.RealmModel;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultEvaluationContext implements EvaluationContext {

    private final List<ResourcePermission> permissions;
    private final RealmModel realm;
    private final ExecutionContext executionContext;
    private final Identity identity;
    private boolean granted;

    public DefaultEvaluationContext(Identity identity, RealmModel realm, List<ResourcePermission> permissions, ExecutionContext executionContext) {
        this.identity = identity;
        this.realm = realm;
        this.permissions = permissions;
        this.executionContext = executionContext;
    }

    @Override
    public List<ResourcePermission> getAllPermissions() {
        return this.permissions;
    }

    @Override
    public boolean hasResource(String resourceName) {
        return this.permissions.stream().filter(resourcePermission -> resourcePermission.getResource().getName().equals(resourceName))
                .findFirst().isPresent();
    }

    @Override
    public boolean hasScope(String scopeName) {
        return this.permissions.stream().filter(resourcePermission -> resourcePermission.getScopes().stream().filter(scope -> scope.getName().equals(scopeName)).findFirst().isPresent())
                .findFirst().isPresent();
    }

    @Override
    public boolean hasPermission(String resourceName, String... scopes) {
        return this.permissions.stream().filter(new Predicate<ResourcePermission>() {
            @Override
            public boolean test(ResourcePermission resourcePermission) {
                if (!resourcePermission.getResource().getName().equals(resourceName)) {
                    return false;
                }

                return resourcePermission.getScopes().stream().map(new Function<Scope, String>() {
                    @Override
                    public String apply(Scope scope) {
                        return scope.getName();
                    }
                }).collect(Collectors.toList()).containsAll(Arrays.asList(scopes));
            }
        }).findFirst().isPresent();
    }

    @Override
    public Resource getResource(String resourceName) {
        ResourcePermission permission = this.permissions.stream().filter(resourcePermission -> resourcePermission.getResource().getName().equals(resourceName))
                .findFirst().orElse(null);

        if (permission == null) {
            return permission.getResource();
        }

        return null;
    }

    @Override
    public Scope getScope(String scopeName) {
        return this.permissions.stream().flatMap(new Function<ResourcePermission, Stream<Scope>>() {
            @Override
            public Stream<Scope> apply(ResourcePermission resourcePermission) {
                return resourcePermission.getScopes().stream();
            }
        }).filter(new Predicate<Scope>() {
            @Override
            public boolean test(Scope scope) {
                return scope.getName().equals(scopeName);
            }
        }).findAny().orElse(null);
    }

    @Override
    public Identity getIdentity() {
        return this.identity;
    }

    @Override
    public RealmModel getRealm() {
        return this.realm;
    }

    public ExecutionContext getExecutionContext() {
        return this.executionContext;
    }

    @Override
    public void grant() {
        this.granted = true;
    }

    @Override
    public boolean isGranted() {
        return granted;
    }
}
