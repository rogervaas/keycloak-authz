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
package org.keycloak.authz.server.uma.authorization;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.Identity;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.policy.EvaluationContext;
import org.keycloak.authz.core.policy.EvaluationResult;
import org.keycloak.authz.core.policy.ExecutionContext;
import org.keycloak.authz.server.services.core.KeycloakIdentity;
import org.keycloak.authz.server.uma.protection.permission.PermissionTicket;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.Consumes;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationService {

    private final RealmModel realm;
    private final Authorization authorizationManager;
    private final KeycloakSession keycloakSession;

    @Context
    private HttpRequest request;

    public AuthorizationService(RealmModel realm,Authorization authorization,  KeycloakSession keycloakSession) {
        this.realm = realm;
        this.authorizationManager = authorization;
        this.keycloakSession = keycloakSession;
    }

    @OPTIONS
    public Response authorizepPreFlight() {
        return Cors.add(this.request, Response.ok()).auth().preflight().build();
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response authorize(AuthorizationRequest request) {
        Identity identity = KeycloakIdentity.create(this.realm, this.keycloakSession);

        if (!identity.hasRole("uma_authorization")) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires uma_authorization scope.", Response.Status.FORBIDDEN);
        }

        PermissionTicket ticket = verifyPermissionTicket(request);
        EvaluationContext evaluationContext = createEvaluationContext(identity, ticket);

        List<EvaluationResult> evaluate = this.authorizationManager.getPolicyManager().evaluate(evaluationContext);

        if (evaluationContext.isGranted()) {
            return Cors.add(this.request, Response.status(Response.Status.CREATED).entity(new AuthorizationResponse(createRequestingPartyToken(identity, evaluate)))).allowedOrigins("*").build();
        }

        throw new ErrorResponseException("not_authorized", "Authorization  denied for resource [" + ticket.getResourceSetId() + "].", Response.Status.FORBIDDEN);
    }

    private EvaluationContext createEvaluationContext(Identity identity, PermissionTicket ticket) {
        List<Scope> scopes = new ArrayList<>();

        for (String scopeName : ticket.getScopes()) {
            scopes.add(this.authorizationManager.getStoreFactory().scope().findByName(scopeName));
        }

        ResourcePermission permission = new ResourcePermission(this.authorizationManager.getStoreFactory().resource().findById(ticket.getResourceSetId()), scopes);

        return new DefaultEvaluationContext(identity, this.realm, Arrays.asList(permission), ExecutionContext.EMPTY);
    }

    private String createRequestingPartyToken(Identity identity, List<EvaluationResult> evaluation) {
        List<Permission> permissions = evaluation.stream().map(new Function<EvaluationResult, Permission>() {
            @Override
            public Permission apply(EvaluationResult evaluationResult) {
                ResourcePermission permission = evaluationResult.getPermission();
                Set<String> scopes = permission.getScopes().stream().map(new Function<Scope, String>() {
                    @Override
                    public String apply(Scope scope) {
                        return scope.getName();
                    }
                }).collect(Collectors.toSet());
                return new Permission(permission.getResource().getId(), scopes);
            }
        }).collect(Collectors.toList());
        return new JWSBuilder().jsonContent(new RequestingPartyToken(
                identity.getId(),
                permissions.toArray(new Permission[permissions.size()]))).rsa256(this.realm.getPrivateKey()
        );
    }

    private PermissionTicket verifyPermissionTicket(AuthorizationRequest request) {
        try {
            JWSInput jws = new JWSInput(request.getTicket());

            if (!RSAProvider.verify(jws, this.realm.getPublicKey())) {
                throw new ErrorResponseException("invalid_ticket", "Ticket verification failed", Response.Status.BAD_REQUEST);
            }

            //TODO: more validations are required, like issuer, audience, expiration and so forth.

            return jws.readJsonContent(PermissionTicket.class);
        } catch (Exception e) {
            throw new ErrorResponseException("invalid_ticket", "Unexpected error while validating ticket.", Response.Status.BAD_REQUEST);
        }
    }
}