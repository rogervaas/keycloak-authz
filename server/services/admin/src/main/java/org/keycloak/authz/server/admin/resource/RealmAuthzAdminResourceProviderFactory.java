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
package org.keycloak.authz.server.admin.resource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.Config;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.policy.spi.PolicyProviderFactory;
import org.keycloak.authz.core.store.spi.PersistenceProvider;
import org.keycloak.authz.persistence.PersistenceProviderFactory;
import org.keycloak.authz.server.admin.KeycloakAuthorizationManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.admin.spi.RealmAdminResourceProvider;
import org.keycloak.services.resources.admin.spi.RealmAdminResourceProviderFactory;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(RealmAdminResourceProviderFactory.class)
public class RealmAuthzAdminResourceProviderFactory implements RealmAdminResourceProviderFactory {

    private PersistenceProviderFactory persistenceProviderFactory;
    private List<PolicyProviderFactory> policyProviders = new ArrayList<>();

    @Override
    public RealmAdminResourceProvider create(RealmModel realm, KeycloakSession keycloakSession) {
        return new RealmAdminResourceProvider() {
            public Object getResource(final String pathName) {
                if (pathName.equals("authz")) {
                    RootResource resource = new RootResource(realm);

                    ResteasyProviderFactory.getInstance().pushContext(Authorization.class, createAuthorizationManager(keycloakSession));
                    ResteasyProviderFactory.getInstance().injectProperties(resource);

                    return resource;
                }

                return null;
            }

            public void close() {
            }
        };
    }

    @Override
    public RealmAdminResourceProvider create(KeycloakSession session) {
        throw new RuntimeException("Use create(RealmModel, KeycloakSession) instead.");
    }

    @Override
    public void init(Config.Scope config) {
        this.persistenceProviderFactory = createPersistenceProvider();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        initPolicyProviders(factory);
        this.persistenceProviderFactory.registerSynchronizationListeners(factory);
    }

    @Override
    public void close() {
        this.policyProviders.forEach(PolicyProviderFactory::dispose);
    }

    @Override
    public String getId() {
        return "keycloak-authz-admin-restapi";
    }

    private Authorization createAuthorizationManager(KeycloakSession keycloakSession) {
        return new KeycloakAuthorizationManager(this.persistenceProviderFactory.create(keycloakSession), this.policyProviders);
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        HashMap<String, String> info = new HashMap<>();
        StringBuilder policyProvidersInfo = new StringBuilder();

        this.policyProviders.forEach(provider -> policyProvidersInfo.append(provider.getType()).append(", "));

        info.put("Persistence Provider", this.persistenceProviderFactory.getClass().getName());
        info.put("Policy Providers", policyProvidersInfo.substring(0, policyProvidersInfo.lastIndexOf(",")));

        return info;
    }

    private PersistenceProviderFactory createPersistenceProvider() {
        ServiceLoader<PersistenceProviderFactory> providers = ServiceLoader.load(PersistenceProviderFactory.class, getClass().getClassLoader());

        if (providers.iterator().hasNext()) {
            return providers.iterator().next();
        }

        throw new RuntimeException("No persistence provider found.");
    }

    private void initPolicyProviders(KeycloakSessionFactory factory) {
        KeycloakSession session = factory.create();
        KeycloakTransactionManager transaction = session.getTransaction();
        try {
            transaction.begin();

            ServiceLoader.load(PolicyProviderFactory.class, getClass().getClassLoader()).forEach(providerFactory -> {
                PersistenceProvider persistenceProvider = this.persistenceProviderFactory.create(session);

                providerFactory.init(persistenceProvider.getPolicyStore());

                this.policyProviders.add(providerFactory);
            });

            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
        } finally {
            session.close();
        }
    }

    private AccessToken getAccessToken(KeycloakSession keycloakSession, RealmModel realm) {
        AppAuthManager authManager = new AppAuthManager();
        AuthenticationManager.AuthResult authResult = authManager.authenticateBearerToken(keycloakSession, realm, keycloakSession.getContext().getUri(), keycloakSession.getContext().getConnection(), keycloakSession.getContext().getRequestHeaders());

        if (authResult != null) {
            return authResult.getToken();
        }

        return null;
    }
}
