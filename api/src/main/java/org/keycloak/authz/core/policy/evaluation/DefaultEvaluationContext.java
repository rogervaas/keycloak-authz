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
package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.models.RealmModel;

import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see EvaluationContext
 */
public class DefaultEvaluationContext implements EvaluationContext {

    private final Supplier<ResourcePermission> permissionSupplier;
    private final RealmModel realm;
    private final ExecutionContext executionContext;
    private final Identity identity;
    private boolean granted;

    public DefaultEvaluationContext(Identity identity, RealmModel realm, Supplier<ResourcePermission> permissionSupplier, ExecutionContext executionContext) {
        this.identity = identity;
        this.realm = realm;
        this.permissionSupplier = permissionSupplier;
        this.executionContext = executionContext;
    }

    @Override
    public Supplier<ResourcePermission> getPermissions() {
        return this.permissionSupplier;
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
    public boolean isGranted() {
        return granted;
    }
}
