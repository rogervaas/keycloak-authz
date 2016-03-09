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

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.server.admin.resource.representation.ResourceRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ScopeRepresentation;
import org.keycloak.authz.server.admin.resource.util.Models;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceSetResource {

    private final RealmModel realm;
    private ResourceServer resourceServer;

    @Context
    private Authorization authorizationManager;

    @Context
    private KeycloakSession keycloakSession;

    public ResourceSetResource(RealmModel realm, ResourceServer resourceServer, Authorization authorizationManager, KeycloakSession keycloakSession) {
        this.realm = realm;
        this.resourceServer = resourceServer;
        this.authorizationManager = authorizationManager;
        this.keycloakSession = keycloakSession;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response create(ResourceRepresentation resource) {
        Resource existingResource = this.authorizationManager.getStoreFactory().resource().findByName(resource.getName());

        if (existingResource != null && existingResource.getResourceServer().getId().equals(this.resourceServer.getId())) {
            return ErrorResponse.exists("Resource with name [" + resource.getName() + "] already exists.");
        }

        Resource model = Models.toModel(resource, this.resourceServer, this.authorizationManager);

        this.authorizationManager.getStoreFactory().resource().save(model);

        ResourceRepresentation representation = new ResourceRepresentation();

        representation.setId(model.getId());

        return Response.status(Response.Status.CREATED).entity(representation).build();
    }

    @Path("{id}")
    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response update(@PathParam("id") String id, ResourceRepresentation resource) {
        Resource model = this.authorizationManager.getStoreFactory().resource().findById(resource.getId());

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        model.setName(resource.getName());
        model.setType(resource.getType());
        model.setUri(resource.getUri());
        model.setIconUri(resource.getIconUri());

        model.updateScopes(resource.getScopes().stream()
                .map((ScopeRepresentation scope) -> Models.toModel(scope, this.resourceServer, this.authorizationManager))
                .collect(Collectors.toSet()));

        this.authorizationManager.getStoreFactory().resource().save(model);

        return Response.noContent().build();
    }

    @Path("{id}")
    @DELETE
    public Response delete(@PathParam("id") String id) {
        Resource resource = this.authorizationManager.getStoreFactory().resource().findById(id);

        if (resource == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        List<Policy> policies = this.authorizationManager.getStoreFactory().policy().findByResource(id);

        for (Policy policyModel : policies) {
            if (policyModel.getResources().size() == 1) {
                this.authorizationManager.getStoreFactory().policy().delete(policyModel.getId());
            } else {
                policyModel.removeResource(resource);
                this.authorizationManager.getStoreFactory().policy().save(policyModel);
            }
        }

        this.authorizationManager.getStoreFactory().resource().delete(id);

        return Response.noContent().build();
    }

    @Path("{id}")
    @GET
    @Produces("application/json")
    public Response findById(@PathParam("id") String id) {
        Resource model = this.authorizationManager.getStoreFactory().resource().findById(id);

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        return Response.ok(Models.toRepresentation(model, this.resourceServer, this.authorizationManager, this.realm, this.keycloakSession)).build();
    }

    @GET
    @Produces("application/json")
    public Response findAll() {
        return Response.ok(
                this.authorizationManager.getStoreFactory().resource().findByResourceServer(this.resourceServer.getId()).stream()
                        .map(resource -> Models.toRepresentation(resource, this.resourceServer, this.authorizationManager, this.realm, this.keycloakSession))
                        .collect(Collectors.toList()))
                .build();
    }
}
