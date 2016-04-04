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
import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.evaluation.DecisionResultCollector;
import org.keycloak.authz.core.policy.evaluation.Result;
import org.keycloak.authz.server.services.common.DefaultExecutionContext;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.stream.Collectors;

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

        this.authorizationManager.evaluators().schedule(createPermissions(client), new DefaultExecutionContext(this.identity, this.realm), Executors.newSingleThreadExecutor(this.threadFactory)).evaluate(new DecisionResultCollector() {

            @Override
            public void onError(Throwable cause) {
                asyncResponse.resume(cause);
            }

            @Override
            protected void onComplete(List<Result> results) {
                asyncResponse.resume(Cors.add(request, Response.ok().entity(new EntitlementResponse(createRequestingPartyToken(identity, results)))).allowedOrigins("*").build());
            }
        });
    }

    public List<ResourcePermission> createPermissions(ClientModel client) {
        ResourceServer resourceServer = this.authorizationManager.getStoreFactory().getResourceServerStore().findByClient(client.getId());

        return this.authorizationManager.getStoreFactory().getResourceStore().findByResourceServer(resourceServer.getId()).stream()
                .flatMap(resource -> {
                    List<Scope> scopes = resource.getScopes();

                    if (scopes.isEmpty()) {
                        return Arrays.asList(new ResourcePermission(resource, Collections.emptyList())).stream();
                    }

                    return scopes.stream().map(scope -> new ResourcePermission(resource, Arrays.asList(scope)));
                }).collect(Collectors.toList());
    }

    private String createRequestingPartyToken(Identity identity, List<Result> evaluation) {
        List<Permission> permissions = evaluation.stream()
                .filter(evaluationResult -> evaluationResult.getStatus().equals(Decision.Effect.PERMIT))
                .map(evaluationResult -> {
                    ResourcePermission permission = evaluationResult.getPermission();
                    return new Permission(permission.getResource().getId(), permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList()));
                }).collect(Collectors.toList());

        Map<String, Permission> perms = new HashMap<>();

        permissions.forEach(permission -> {
            Permission evalPermission = perms.get(permission.getResourceSetId());

            if (evalPermission == null) {
                evalPermission = permission;
                perms.put(permission.getResourceSetId(), evalPermission);
            }

            List<String> scopes = evalPermission.getScopes();

            permission.getScopes().forEach(s -> {
                if (!scopes.contains(s)) {
                    scopes.add(s);
                }
            });
        });

        AccessToken accessToken = Tokens.getAccessToken(this.realm);
        String accessTokenAsString = Tokens.getAccessTokenAsString();

        return new JWSBuilder().jsonContent(new EntitlementToken(perms.values().stream().collect(Collectors.toList()), accessToken, accessTokenAsString))
                .rsa256(this.realm.getPrivateKey());
    }
}
