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
package org.keycloak.authz.server.entitlement.resource;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.policy.evaluation.DecisionResultCollector;
import org.keycloak.authz.core.policy.evaluation.Result;
import org.keycloak.authz.server.entitlement.resource.representation.EntitlementResponse;
import org.keycloak.authz.server.services.common.KeycloakExecutionContext;
import org.keycloak.authz.server.services.common.util.Permissions;
import org.keycloak.authz.server.services.common.util.Tokens;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

import static org.keycloak.authz.server.services.common.util.Permissions.entitlements;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EntitlementResource {

    private final RealmModel realm;
    private final ThreadFactory threadFactory;

    @Context
    private Authorization authorizationManager;

    @Context
    private Identity identity;

    @Context
    private HttpRequest request;

    EntitlementResource(RealmModel realm, ThreadFactory threadFactory) {
        this.realm = realm;
        this.threadFactory = threadFactory;
    }

    @OPTIONS
    public Response authorizePreFlight() {
        return Cors.add(this.request, Response.ok()).auth().preflight().build();
    }

    @GET
    @Produces("application/json")
    public void get(@QueryParam("resourceServerId") String resourceServerId, @Suspended AsyncResponse asyncResponse) {
        if (resourceServerId == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Requires resourceServerId request parameter.", Response.Status.BAD_REQUEST);
        }

        if (!this.identity.hasRole("kc_entitlement")) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires kc_entitlement scope.", Response.Status.FORBIDDEN);
        }

        ClientModel client = this.realm.getClientByClientId(resourceServerId);

        if (client == null) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Identifier is not associated with any client and resource server.", Response.Status.BAD_REQUEST);
        }

        ResourceServer resourceServer = this.authorizationManager.getStoreFactory().getResourceServerStore().findByClient(client.getId());

        if (!resourceServer.isAllowEntitlements()) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "Server does support entitlements.", Response.Status.BAD_REQUEST);
        }

        this.authorizationManager.evaluators().schedule(Permissions.all(resourceServer, this.identity, this.authorizationManager), new KeycloakExecutionContext(this.realm), Executors.newSingleThreadExecutor(this.threadFactory)).evaluate(new DecisionResultCollector() {

            @Override
            public void onError(Throwable cause) {
                asyncResponse.resume(cause);
            }

            @Override
            protected void onComplete(List<Result> results) {
                asyncResponse.resume(Cors.add(request, Response.ok().entity(new EntitlementResponse(createRequestingPartyToken(results)))).allowedOrigins("*").build());
            }
        });
    }

    private String createRequestingPartyToken(List<Result> results) {
        AccessToken accessToken = Tokens.getAccessToken(this.realm);
        String accessTokenAsString = Tokens.getAccessTokenAsString();

        return new JWSBuilder().jsonContent(new EntitlementToken(entitlements(results), accessToken, accessTokenAsString))
                .rsa256(this.realm.getPrivateKey());
    }
}
