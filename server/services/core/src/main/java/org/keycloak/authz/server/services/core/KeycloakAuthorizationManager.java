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
package org.keycloak.authz.server.services.core;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.policy.DefaultPolicyManager;
import org.keycloak.authz.core.policy.PolicyManager;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.StoreFactory;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakAuthorizationManager implements Authorization {

    private final StoreFactory storeFactory;
    private final List<PolicyProviderFactory> policyProviders;

    public KeycloakAuthorizationManager(StoreFactory storeFactory, List<PolicyProviderFactory> policyProviders) {
        this.storeFactory = storeFactory;
        this.policyProviders = policyProviders;
    }

    @Override
    public PolicyManager getPolicyManager() {
        return new DefaultPolicyManager(getStoreFactory().getPolicyStore(), this.policyProviders);
    }

    @Override
    public StoreFactory getStoreFactory() {
        return this.storeFactory;
    }
}
