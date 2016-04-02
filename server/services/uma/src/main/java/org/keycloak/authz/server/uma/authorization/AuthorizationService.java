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
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.policy.evaluation.DefaultEvaluationContext;
import org.keycloak.authz.core.policy.evaluation.EvaluationContext;
import org.keycloak.authz.core.policy.evaluation.EvaluationResult;
import org.keycloak.authz.server.services.core.DefaultExecutionContext;
import org.keycloak.authz.server.services.core.KeycloakIdentity;
import org.keycloak.authz.server.services.core.util.Tokens;
import org.keycloak.authz.server.uma.protection.permission.PermissionTicket;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.Consumes;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    public AuthorizationService(RealmModel realm, Authorization authorization, KeycloakSession keycloakSession) {
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
        KeycloakIdentity identity = KeycloakIdentity.create(this.realm, this.keycloakSession);

        if (!identity.hasRole("uma_authorization")) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires uma_authorization scope.", Response.Status.FORBIDDEN);
        }

        PermissionTicket ticket = verifyPermissionTicket(request);
        EvaluationContext evaluationContext = createEvaluationContext(identity, ticket, request);
//        List<EvaluationResult> evaluate = this.authorizationManager.getPolicyManager().evaluate(evaluationContext);
        List<EvaluationResult> evaluate = null;

        if (evaluationContext.isGranted()) {
            return Cors.add(this.request, Response.status(Response.Status.CREATED).entity(new AuthorizationResponse(createRequestingPartyToken(identity, evaluate)))).allowedOrigins("*").build();
        }

        throw new ErrorResponseException("not_authorized", "Authorization  denied for resource [" + ticket.getResourceSetId() + "].", Response.Status.FORBIDDEN);
    }

    private EvaluationContext createEvaluationContext(Identity identity, PermissionTicket ticket, AuthorizationRequest request) {
        Map<String, Set<String>> permissionsToEvaluate = new HashMap<>();

        permissionsToEvaluate.put(ticket.getResourceSetId(), ticket.getScopes());

        String rpt = request.getRpt();

        if (rpt != null && !"".equals(rpt)) {
            if (!Tokens.verifySignature(rpt, this.realm.getPublicKey())) {
                throw new ErrorResponseException("invalid_rpt", "RPT signature is invalid", Response.Status.BAD_REQUEST);
            }

            RequestingPartyToken requestingPartyToken;

            try {
                requestingPartyToken = new JWSInput(rpt).readJsonContent(RequestingPartyToken.class);
            } catch (JWSInputException e) {
                throw new ErrorResponseException("invalid_rpt", "Invalid RPT", Response.Status.BAD_REQUEST);
            }

            if (requestingPartyToken.isValid()) {
                requestingPartyToken.getPermissions().forEach(permission -> {
                    Resource resource = authorizationManager.getStoreFactory().getResourceStore().findById(permission.getResourceSetId());

                    if (resource != null) {
                        Set<String> scopes = permissionsToEvaluate.get(permission.getResourceSetId());

                        if (scopes == null) {
                            scopes = new HashSet<>();
                            permissionsToEvaluate.put(permission.getResourceSetId(), scopes);
                        }

                        scopes.addAll(permission.getScopes());
                    }
                });
            }
        }

        Iterator<ResourcePermission> finalPermissions = permissionsToEvaluate.entrySet().stream().map(entry -> {
            Resource resource = authorizationManager.getStoreFactory().getResourceStore().findById(entry.getKey());

            if (resource != null) {
                List<Scope> scopes = entry.getValue().stream()
                        .map(scopeName -> authorizationManager.getStoreFactory().getScopeStore().findByName(scopeName))
                        .filter(scope -> scope != null).collect(Collectors.toList());

                return new ResourcePermission(resource, scopes);
            }

            return null;
        }).filter(resourcePermission -> resourcePermission != null).collect(Collectors.toList()).iterator();

        return new DefaultEvaluationContext(identity, this.realm, () -> finalPermissions.hasNext() ? finalPermissions.next() : null, new DefaultExecutionContext(this.keycloakSession, this.realm));
    }

    private String createRequestingPartyToken(Identity identity, List<EvaluationResult> evaluation) {
        List<Permission> permissions = evaluation.stream().map(evaluationResult -> {
            ResourcePermission permission = evaluationResult.getPermission();
            Set<String> scopes = permission.getScopes().stream().map(Scope::getName).collect(Collectors.toSet());
            return new Permission(permission.getResource().getId(), scopes);
        }).collect(Collectors.toList());

        AccessToken accessToken = Tokens.getAccessToken(this.keycloakSession, this.realm);

        return new JWSBuilder().jsonContent(new RequestingPartyToken(accessToken, Tokens.getAccessTokenAsString(this.keycloakSession),
                permissions.toArray(new Permission[permissions.size()]))).rsa256(this.realm.getPrivateKey()
        );
    }

    private PermissionTicket verifyPermissionTicket(AuthorizationRequest request) {
        if (!Tokens.verifySignature(request.getTicket(), this.realm.getPublicKey())) {
            throw new ErrorResponseException("invalid_ticket", "Ticket verification failed", Response.Status.BAD_REQUEST);
        }

        try {
            return new JWSInput(request.getTicket()).readJsonContent(PermissionTicket.class);
        } catch (JWSInputException e) {
            throw new ErrorResponseException("invalid_ticket", "Could not parse permission ticket.", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}