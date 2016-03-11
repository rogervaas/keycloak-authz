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
package org.keycloak.authz.server.admin.resource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.server.admin.resource.representation.ScopeRepresentation;
import org.keycloak.authz.server.admin.resource.util.Models;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponse;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import static org.keycloak.authz.server.admin.resource.util.Models.toModel;
import static org.keycloak.authz.server.admin.resource.util.Models.toRepresentation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ScopeResource {

    @Context
    private Authorization authorizationManager;

    @Context
    private KeycloakSession keycloakSession;

    private ResourceServer resourceServer;

    public ScopeResource(ResourceServer resourceServer) {
        this.resourceServer = resourceServer;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response create(ScopeRepresentation scope) {
        Scope model = toModel(scope, this.resourceServer, this.authorizationManager);

        this.authorizationManager.getStoreFactory().getScopeStore().save(model);

        scope.setId(model.getId());

        return Response.status(Response.Status.CREATED).entity(scope).build();
    }

    @Path("{id}")
    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response update(@PathParam("id") String id, ScopeRepresentation scope) {
        Scope model = this.authorizationManager.getStoreFactory().getScopeStore().findById(scope.getId());

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        model.setName(scope.getName());
        model.setIconUri(scope.getIconUri());

        this.authorizationManager.getStoreFactory().getScopeStore().save(model);

        return Response.noContent().build();
    }

    @Path("{id}")
    @DELETE
    public Response delete(@PathParam("id") String id) {
        List<Resource> resources = this.authorizationManager.getStoreFactory().getResourceStore().findByScope(id);

        if (!resources.isEmpty()) {
            return ErrorResponse.exists("Scopes can not be removed while associated with resources.");
        }

        Scope model = this.authorizationManager.getStoreFactory().getScopeStore().findById(id);

        List<Policy> policies = this.authorizationManager.getStoreFactory().getPolicyStore().findByScopeName(Arrays.asList(model.getName()));

        for (Policy policyModel : policies) {
            if (policyModel.getScopes().size() == 1) {
                this.authorizationManager.getStoreFactory().getPolicyStore().remove(policyModel.getId());
            } else {
                policyModel.removeScope(model);
                this.authorizationManager.getStoreFactory().getPolicyStore().save(policyModel);
            }
        }

        this.authorizationManager.getStoreFactory().getScopeStore().delete(id);

        return Response.noContent().build();
    }

    @Path("{id}")
    @GET
    @Produces("application/json")
    public Response findById(@PathParam("id") String id) {
        Scope model = this.authorizationManager.getStoreFactory().getScopeStore().findById(id);

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        return Response.ok(toRepresentation(model)).build();
    }

    @GET
    @Produces("application/json")
    public Response findAll() {
        return Response.ok(
                this.authorizationManager.getStoreFactory().getScopeStore().findByResourceServer(this.resourceServer.getId()).stream()
                        .map(scope -> Models.toRepresentation(scope))
                        .collect(Collectors.toList()))
                .build();
    }
}
