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

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.Config;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.authz.persistence.PersistenceProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.admin.RealmAdminResourceProvider;
import org.keycloak.services.resource.admin.RealmAdminResourceProviderFactory;
import org.kohsuke.MetaInfServices;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(RealmAdminResourceProviderFactory.class)
public class RealmAuthzAdminResourceProviderFactory implements RealmAdminResourceProviderFactory {

    private PersistenceProviderFactory persistenceProviderFactory;
    private List<PolicyProviderFactory> policyProviders = new ArrayList<>();
    private Authorization authorization;

    @Override
    public RealmAdminResourceProvider create(RealmModel realm, KeycloakSession keycloakSession) {
        return new RealmAdminResourceProvider() {
            public Object getResource(final String pathName) {
                if (pathName.equals("authz")) {
                    RootResource resource = new RootResource(realm);

                    ResteasyProviderFactory.getInstance().pushContext(StoreFactory.class, persistenceProviderFactory.create(keycloakSession));
                    ResteasyProviderFactory.getInstance().pushContext(Authorization.class, authorization);
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
        KeycloakSession session = factory.create();
        KeycloakTransactionManager transaction = session.getTransaction();
        try {
            transaction.begin();

            this.authorization = Authorization.builder().storeFactory(() -> {
                StoreFactory storeFactory = ResteasyProviderFactory.getContextData(StoreFactory.class);

                if (storeFactory == null) {
                    return persistenceProviderFactory.create(session);
                }

                return storeFactory;
            }).build();

            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
        } finally {
            session.close();
        }
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

    @Override
    public Map<String, String> getOperationalInfo() {
        HashMap<String, String> info = new HashMap<>();
        StringBuilder policyProvidersInfo = new StringBuilder();

        this.authorization.getProviderFactories().forEach(provider -> policyProvidersInfo.append(provider.getType()).append(", "));

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
}
