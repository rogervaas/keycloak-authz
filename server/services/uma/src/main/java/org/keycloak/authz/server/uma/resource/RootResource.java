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

import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.OAuthErrorException;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.server.services.core.KeycloakIdentity;
import org.keycloak.authz.server.uma.authorization.AuthorizationService;
import org.keycloak.authz.server.uma.config.Configuration;
import org.keycloak.authz.server.uma.config.ConfigurationService;
import org.keycloak.authz.server.uma.protection.permission.PermissionService;
import org.keycloak.authz.server.uma.protection.resource.ResourceService;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RootResource {

    private final RealmModel realm;
    private final Authorization authorizationManager;
    private final KeycloakSession keycloakSession;
    private final Configuration configuration;

    @Context
    private HttpRequest request;

    public RootResource(RealmModel realm, Authorization authorizationManager, KeycloakSession keycloakSession, Configuration configuration) {
        this.realm = realm;
        this.authorizationManager = authorizationManager;
        this.keycloakSession = keycloakSession;
        this.configuration = configuration;
    }

    @Path("/resource_set")
    public Object resource() {
        KeycloakIdentity identity = createIdentity();

        if (!identity.hasRole("uma_protection")) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires uma_protection scope.", Response.Status.FORBIDDEN);
        }

        ResourceService resource = new ResourceService(this.realm, getResourceServer(identity), identity, this.authorizationManager, this.keycloakSession);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/permission")
    public Object permission() {
        KeycloakIdentity identity = createIdentity();

        if (!identity.hasRole("uma_protection")) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires uma_protection scope.", Response.Status.FORBIDDEN);
        }

        PermissionService resource = new PermissionService(this.realm, getResourceServer(identity), this.authorizationManager);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/authorize")
    public Object authorize() {
        AuthorizationService resource = new AuthorizationService(this.realm, this.authorizationManager, this.keycloakSession);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("/uma_configuration")
    public ConfigurationService configuration() {
        ConfigurationService resource = new ConfigurationService(this.configuration);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    private KeycloakIdentity createIdentity() {
        return KeycloakIdentity.create(realm, keycloakSession);
    }

    private ResourceServer getResourceServer(Identity identity) {
        ClientModel clientApplication = realm.getClientById(identity.getId());

        if (clientApplication == null) {
            throw new ErrorResponseException("invalid_clientId", "Client application with id [" + identity.getId() + "] does not exist in realm [" + this.realm.getName() + "]", Response.Status.BAD_REQUEST);
        }

        ResourceServer resourceServer = this.authorizationManager.getStoreFactory().getResourceServerStore().findByClient(identity.getId());

        if (resourceServer == null) {
            throw new ErrorResponseException("invalid_clientId", "Client application [" + clientApplication.getClientId() + "] is not registered as resource server.", Response.Status.FORBIDDEN);
        }

        return resourceServer;
    }
}
