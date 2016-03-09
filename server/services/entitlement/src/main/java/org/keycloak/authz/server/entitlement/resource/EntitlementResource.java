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
import org.keycloak.authz.core.Identity;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.policy.EvaluationContext;
import org.keycloak.authz.core.policy.EvaluationResult;
import org.keycloak.authz.core.policy.ExecutionContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EntitlementResource {

    private final RealmModel realm;
    private final KeycloakSession keycloakSession;

    @Context
    private Authorization authorizationManager;

    @Context
    private Identity identity;

    @Context
    private HttpRequest request;

    EntitlementResource(RealmModel realm, KeycloakSession keycloakSession) {
        this.realm = realm;
        this.keycloakSession = keycloakSession;
    }

    @OPTIONS
    public Response authorizePreFlight() {
        return Cors.add(this.request, Response.ok()).auth().preflight().build();
    }

    @GET
    @Produces("application/json")
    public Response resource(@QueryParam("resourceServerId") String resourceServerId) {
        if (!this.identity.hasRole("kc_entitlement")) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires kc_entitlement scope.", Response.Status.FORBIDDEN);
        }

        ClientModel client = this.realm.getClientByClientId(resourceServerId);
        ResourceServer resourceServer = this.authorizationManager.getStoreFactory().resourceServer().findByClient(client.getId());
        ArrayList<ResourcePermission> permissions = new ArrayList<>();

        permissions.addAll(this.authorizationManager.getStoreFactory().resource().findByResourceServer(resourceServer.getId()).stream()
                .flatMap(new Function<Resource, Stream<ResourcePermission>>() {
                    @Override
                    public Stream<ResourcePermission> apply(Resource resource) {
                        List<Scope> scopes = resource.getScopes();

                        if (scopes.isEmpty()) {
                            return Arrays.asList(new ResourcePermission(resource, Collections.emptyList())).stream();
                        }

                        return scopes.stream().map(new Function<Scope, ResourcePermission>() {
                            @Override
                            public ResourcePermission apply(Scope scope) {
                                return new ResourcePermission(resource, Arrays.asList(scope));
                            }
                        });
                    }
                }).collect(Collectors.toList()));

        EvaluationContext evaluationContext = createEvaluationContext(identity, permissions);

        List<EvaluationResult> evaluate = this.authorizationManager.getPolicyManager().evaluate(evaluationContext);

        return Cors.add(this.request, Response.status(Response.Status.CREATED).entity(new EntitlementResponse(createRequestingPartyToken(identity, evaluate)))).allowedOrigins("*").build();
    }

    private String createRequestingPartyToken(Identity identity, List<EvaluationResult> evaluation) {
        List<Permission> permissions = evaluation.stream().filter(new Predicate<EvaluationResult>() {
            @Override
            public boolean test(EvaluationResult evaluationResult) {
                return evaluationResult.getStatus().equals(EvaluationResult.PolicyResult.Status.GRANTED);
            }
        }).map(new Function<EvaluationResult, Permission>() {
            @Override
            public Permission apply(EvaluationResult evaluationResult) {
                ResourcePermission permission = evaluationResult.getPermission();
                return new Permission(permission.getResource().getId(), permission.getScopes().stream().map(new Function<Scope, String>() {
                    @Override
                    public String apply(Scope scope) {
                        return scope.getName();
                    }
                }).collect(Collectors.toList()));
            }
        }).collect(Collectors.toList());

        return new JWSBuilder().jsonContent(new EntitlementToken(
                identity.getId(),
                permissions)).rsa256(this.realm.getPrivateKey()
        );
    }

    private EvaluationContext createEvaluationContext(Identity identity, List<ResourcePermission> permissions) {
        return new DefaultEvaluationContext(identity, this.realm, permissions, ExecutionContext.EMPTY);
    }
}
