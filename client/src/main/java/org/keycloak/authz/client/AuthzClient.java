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
package org.keycloak.authz.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.authz.client.representation.Configuration;
import org.keycloak.authz.client.resource.AuthorizationResource;
import org.keycloak.authz.client.resource.EntitlementResource;
import org.keycloak.authz.client.resource.PermissionResource;
import org.keycloak.authz.client.resource.ProtectedResource;
import org.keycloak.authz.client.resource.ResourceServerResource;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthzClient {

    public static AuthzClient create() {
        InputStream configStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("keycloak-authz.json");

        if (configStream == null) {
            throw new RuntimeException("Could not find any keycloak-authz.json file in classpath.");
        }

        try {
            ClientConfiguration configuration = new ObjectMapper().readValue(configStream, ClientConfiguration.class);

            return create(configuration);
        } catch (IOException e) {
            throw new RuntimeException("Could not create client.", e);
        }
    }

    public static AuthzClient create(ClientConfiguration configuration) {
        return new AuthzClient(configuration);
    }

    private final Configuration serverConfiguration;
    private final ClientConfiguration clientConfiguration;

    private AuthzClient(ClientConfiguration clientConfiguration) {
        if (clientConfiguration == null) {
            throw new IllegalArgumentException("Client configuration can not be null.");
        }

        String configurationUrl = clientConfiguration.getClient().getConfigurationUrl();

        if (configurationUrl == null) {
            throw new IllegalArgumentException("Configuration URL can not be null.");
        }

        Response response = null;

        try {
            response = new ResteasyClientBuilder().build().target(configurationUrl).request().get();

            response.bufferEntity();

            this.serverConfiguration = response.readEntity(Configuration.class);
        } catch (Exception e) {
            String messageFromServer = "No message from server.";

            if (response != null) {
                messageFromServer = response.readEntity(String.class);
            }

            throw new RuntimeException("Unexpected error when trying to obtain the configuration from the authorization server[" + configurationUrl  + "]. Server responded with: " + messageFromServer + ".", e);
        }

        this.clientConfiguration = clientConfiguration;
    }

    public ProtectionClient protection() {
        return obtainPat(this.clientConfiguration.getClient().getClientId(), this.clientConfiguration.getClient().getClientSecret());
    }

    public AuthorizationResource authorization(String accesstoken) {
        ResteasyClient client = new ResteasyClientBuilder().build();
        URI resourceSetRegistrationEndpoint = serverConfiguration.getIssuer();
        return client.target(resourceSetRegistrationEndpoint)
                .register(new BearerAuthFilter(accesstoken))
                .proxy(AuthorizationResource.class);
    }

    public AuthorizationResource authorization(String userName, String password, String clientId) {
        ResteasyClient client = new ResteasyClientBuilder().build();
        URI resourceSetRegistrationEndpoint = serverConfiguration.getIssuer();
        return client.target(resourceSetRegistrationEndpoint)
                .register(new BearerAuthFilter(obtainAccessToken(userName, password, clientId, null).getAccessToken()))
                .proxy(AuthorizationResource.class);
    }

    public EntitlementResource entitlement(String userName, String password, String clientId, String clientSecret) {
        ResteasyClient client = new ResteasyClientBuilder().build();
        return client.target(serverConfiguration.getServerUrl() + "/realms/" + serverConfiguration.getRealm())
                .register(new BearerAuthFilter(obtainAccessToken(userName, password, clientId, clientSecret).getAccessToken()))
                .proxy(EntitlementResource.class);
    }

    public AccessTokenResponse obtainAccessToken(String clientId, String clientSecret) {
        ResteasyClient client = new ResteasyClientBuilder().build();
        ResteasyWebTarget target = client.target(this.serverConfiguration.getTokenEndpoint());
        Form form = new Form();
        form.param("grant_type", "client_credentials");
        target.register(new BasicAuthFilter(clientId, clientSecret));

        return target.request().post(Entity.form(form)).readEntity(AccessTokenResponse.class);
    }

    public AccessTokenResponse obtainAccessToken(String userName, String password, String clientId, String clientSecret) {
        ResteasyClient client = new ResteasyClientBuilder().build();
        ResteasyWebTarget target = client.target(this.serverConfiguration.getTokenEndpoint());
        Form form = new Form();

        form.param("grant_type", "password")
                .param("username", userName)
                .param("password", password);
        target.register(new BasicAuthFilter(clientId, clientSecret));

        return target.request().post(Entity.form(form)).readEntity(AccessTokenResponse.class);
    }

    public Configuration getServerConfiguration() {
        return this.serverConfiguration;
    }

    public AdminClient admin(String userName, String password, String clientId) {
        return new AdminClient(userName, password, clientId);
    }

    private ProtectionClient obtainPat(String clientId, String clientSecret) {
        return new ProtectionClient(obtainAccessToken(clientId, clientSecret).getAccessToken());
    }

    public class ProtectionClient {

        private final String pat;

        private ProtectionClient(String pat) {
            if (pat == null) {
                throw new RuntimeException("No access token was provided when creating client for Protection API.");
            }

            this.pat = pat;
        }

        public ProtectedResource resource() {
            ResteasyClient client = new ResteasyClientBuilder().build();
            URI resourceSetRegistrationEndpoint = serverConfiguration.getIssuer();
            return client.target(resourceSetRegistrationEndpoint)
                    .register(new BearerAuthFilter(this.pat))
                    .proxy(ProtectedResource.class);
        }

        public PermissionResource permission() {
            ResteasyClient client = new ResteasyClientBuilder().build();
            URI resourceSetRegistrationEndpoint = serverConfiguration.getIssuer();
            return client.target(resourceSetRegistrationEndpoint)
                    .register(new BearerAuthFilter(this.pat))
                    .proxy(PermissionResource.class);
        }
    }

    public class AdminClient {

        private final String userName;
        private final String password;
        private final String clientId;

        public AdminClient(String userName, String password, String clientId) {
            this.userName = userName;
            this.password = password;
            this.clientId = clientId;
        }

        public ResourceServerResource resourceServer() {
            Keycloak keycloak = Keycloak.getInstance(serverConfiguration.getServerUrl().toString(), serverConfiguration.getRealm(),
                    this.userName, this.password,
                    this.clientId);

            ResteasyClient client = new ResteasyClientBuilder().build();
            URI resourceSetRegistrationEndpoint = URI.create(serverConfiguration.getServerUrl() + "/admin/realms/" + serverConfiguration.getRealm() + "/authz");
            return client.target(resourceSetRegistrationEndpoint)
                    .register(new BearerAuthFilter(keycloak.tokenManager().getAccessTokenString()))
                    .proxy(ResourceServerResource.class);
        }
    }
}
