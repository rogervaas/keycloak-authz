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
package org.keycloak.authz.server.uma;

import java.util.List;
import org.keycloak.authz.core.policy.DefaultPolicyManager;
import org.keycloak.authz.core.policy.PolicyManager;
import org.keycloak.authz.core.policy.spi.PolicyProviderFactory;
import org.keycloak.authz.core.store.DefaultStoreFactory;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.authz.core.store.spi.PersistenceProvider;
import org.keycloak.authz.server.uma.config.Configuration;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakAuthorizationManager implements UmaAuthorizationManager {

    private final Configuration configuration;
    private final PersistenceProvider persistenceProvider;
    private final List<PolicyProviderFactory> policyProviders;

    public KeycloakAuthorizationManager(PersistenceProvider persistenceProvider, List<PolicyProviderFactory> policyProviders, Configuration configuration) {
        this.persistenceProvider = persistenceProvider;
        this.policyProviders = policyProviders;
        this.configuration = configuration;
    }

    @Override
    public PolicyManager getPolicyManager() {
        return new DefaultPolicyManager(getStoreFactory().policy(), this.policyProviders);
    }

    @Override
    public Configuration configuration() {
        return this.configuration;
    }

    @Override
    public StoreFactory getStoreFactory() {
        return new DefaultStoreFactory(this.persistenceProvider);
    }
}
