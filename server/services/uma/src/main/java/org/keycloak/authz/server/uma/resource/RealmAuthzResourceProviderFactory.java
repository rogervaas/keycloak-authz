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
import org.keycloak.authz.core.policy.spi.PolicyProviderFactory;
import org.keycloak.authz.core.store.spi.PersistenceProvider;
import org.keycloak.authz.persistence.PersistenceProviderFactory;
import org.keycloak.authz.server.uma.KeycloakAuthorizationManager;
import org.keycloak.authz.server.uma.UmaAuthorizationManager;
import org.keycloak.authz.server.uma.config.Configuration;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.spi.RealmResourceProvider;
import org.keycloak.services.resources.spi.RealmResourceProviderFactory;
import org.kohsuke.MetaInfServices;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(RealmResourceProviderFactory.class)
public class RealmAuthzResourceProviderFactory implements RealmResourceProviderFactory {

    private PersistenceProviderFactory persistenceProviderFactory;
    private List<PolicyProviderFactory> policyProviders = new ArrayList<>();

    @Override
    public RealmResourceProvider create(RealmModel realm, KeycloakSession keycloakSession) {
        return new RealmResourceProvider() {
            public Object getResource(final String pathName) {
                if (pathName.equals("authz")) {
                    RootResource resource = new RootResource(realm, createAuthorizationManager(realm, keycloakSession), keycloakSession);

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
        initPolicyProviders(factory);
        this.persistenceProviderFactory.registerSynchronizationListeners(factory);
    }

    @Override
    public void close() {
        this.policyProviders.forEach(PolicyProviderFactory::dispose);
    }

    @Override
    public String getId() {
        return "keycloak-authz-restapi";
    }

    private UmaAuthorizationManager createAuthorizationManager(RealmModel realm, KeycloakSession keycloakSession) {
        return new KeycloakAuthorizationManager(this.persistenceProviderFactory.create(keycloakSession),
                this.policyProviders,
                createConfiguration(realm));
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

    private Configuration createConfiguration(RealmModel realm) {
        return Configuration.fromDefault("http://localhost:8080/auth/", realm.getName(),
                URI.create("http://localhost:8080/auth/realms/" + realm.getName() + "/protocol/openid-connect/token"),
                URI.create("http://localhost:8080/auth/realms/" + realm.getName() + "/protocol/openid-connect/token"));
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
