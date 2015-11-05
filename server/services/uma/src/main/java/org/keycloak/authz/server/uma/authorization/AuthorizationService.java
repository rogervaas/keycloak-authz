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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.policy.ExecutionContext;
import org.keycloak.authz.core.policy.EvaluationContext;
import org.keycloak.authz.core.Identity;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.server.uma.UmaAuthorizationManager;
import org.keycloak.authz.server.uma.protection.permission.PermissionTicket;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.Consumes;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationService {

    private final RealmModel realm;

    @Context
    private UmaAuthorizationManager authorizationManager;

    @Context
    private HttpRequest request;

    @Context
    private Identity identity;

    public AuthorizationService(RealmModel realm) {
        this.realm = realm;
    }

    @OPTIONS
    public Response authorizepPeFlight() {
        return Cors.add(this.request, Response.ok()).auth().preflight().build();
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response authorize(AuthorizationRequest request) {
        PermissionTicket ticket = verifyPermissionTicket(request);
        EvaluationContext evaluationContext = createEvaluationContext(ticket);

        this.authorizationManager.getPolicyManager().evaluate(evaluationContext);

        if (evaluationContext.isGranted()) {
            return Cors.add(this.request, Response.status(Response.Status.CREATED).entity(new AuthorizationResponse(createRequestingPartyToken(ticket)))).allowedOrigins("*").build();
        }

        throw new ErrorResponseException("not_authorized", "Authorization  denied for resource [" + ticket.getResourceSetId() + "].", Response.Status.FORBIDDEN);
    }

    private EvaluationContext createEvaluationContext(PermissionTicket ticket) {
        List<Scope> scopes = new ArrayList<>();

        for (String scopeName : ticket.getScopes()) {
            scopes.add(this.authorizationManager.getStoreFactory().scope().findByName(scopeName));
        }

        ResourcePermission permission = new ResourcePermission(this.authorizationManager.getStoreFactory().resource().findById(ticket.getResourceSetId()), scopes);

        return new DefaultEvaluationContext(identity, this.realm, Arrays.asList(permission), new ExecutionContext() {
            public boolean hasAttribute(final String name, final String... values) {
                return false;
            }
        });
    }

    private String createRequestingPartyToken(PermissionTicket ticket) {
        return new JWSBuilder().jsonContent(new RequestingPartyToken(
                identity.getId(),
                new Permission(ticket.getResourceSetId(), ticket.getScopes()))).rsa256(this.realm.getPrivateKey()
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