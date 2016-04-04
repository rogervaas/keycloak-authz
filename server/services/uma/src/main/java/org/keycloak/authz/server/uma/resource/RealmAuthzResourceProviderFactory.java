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
package org.keycloak.authz.server.uma.resource;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.Config;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.authz.persistence.PersistenceProviderFactory;
import org.keycloak.authz.server.uma.config.Configuration;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.kohsuke.MetaInfServices;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ThreadFactory;
import java.util.function.Supplier;

import static org.jboss.resteasy.spi.ResteasyProviderFactory.getContextDataMap;
import static org.jboss.resteasy.spi.ResteasyProviderFactory.pushContext;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(RealmResourceProviderFactory.class)
public class RealmAuthzResourceProviderFactory implements RealmResourceProviderFactory {

    private PersistenceProviderFactory persistenceProviderFactory;
    private Authorization authorization;
    private ThreadFactory threadFactory;

    @Override
    public RealmResourceProvider create(RealmModel realm, KeycloakSession keycloakSession) {
        return new RealmResourceProvider() {
            public Object getResource(final String pathName) {
                if (pathName.equals("authz")) {
                    RootResource resource = new RootResource(realm, createConfiguration(realm), threadFactory);

                    pushContext(StoreFactory.class, persistenceProviderFactory.create(keycloakSession));
                    pushContext(Authorization.class, authorization);
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
    public RealmResourceProvider create(KeycloakSession session) {
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

            this.authorization = Authorization.builder().storeFactory(new Supplier<StoreFactory>() {
                private boolean initialized = false;

                @Override
                public StoreFactory get() {
                    StoreFactory storeFactory = ResteasyProviderFactory.getContextData(StoreFactory.class);

                    if (!initialized) {
                        initialized = true;
                        return persistenceProviderFactory.create(session);
                    }

                    return storeFactory;
                }
            }).build();

            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
        } finally {
            session.close();
        }
        this.persistenceProviderFactory.registerSynchronizationListeners(factory);
        this.threadFactory = r -> {
            Map<Class<?>, Object> contextDataMap = ResteasyProviderFactory.getInstance().getContextDataMap();

            if (contextDataMap.isEmpty()) {
                System.out.println("Empty !!");
            }

            return new Thread(() -> {
                ResteasyProviderFactory.pushContextDataMap(contextDataMap);
                ResteasyProviderFactory.pushContext(StoreFactory.class, persistenceProviderFactory.create(ResteasyProviderFactory.getContextData(KeycloakSession.class)));
                r.run();
            });
        };
    }

    @Override
    public void close() {
        this.authorization.getProviderFactories().forEach(PolicyProviderFactory::dispose);
    }

    @Override
    public String getId() {
        return "keycloak-authz-restapi";
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

    private Configuration createConfiguration(RealmModel realm) {
        return Configuration.fromDefault("http://localhost:8080/auth/", realm.getName(),
                URI.create("http://localhost:8080/auth/realms/" + realm.getName() + "/protocol/openid-connect/token"),
                URI.create("http://localhost:8080/auth/realms/" + realm.getName() + "/protocol/openid-connect/token"),
                realm.getPublicKeyPem());
    }
}
