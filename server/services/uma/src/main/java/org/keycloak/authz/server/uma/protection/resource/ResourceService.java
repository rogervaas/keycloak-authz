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
package org.keycloak.authz.server.uma.protection.resource;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.server.admin.resource.ResourceSetResource;
import org.keycloak.authz.server.admin.resource.representation.ResourceOwnerRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ResourceRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ScopeRepresentation;
import org.keycloak.authz.server.admin.resource.util.Models;
import org.keycloak.authz.server.uma.ErrorResponse;
import org.keycloak.authz.server.uma.representation.UmaResourceRepresentation;
import org.keycloak.authz.server.uma.representation.UmaScopeRepresentation;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceService {

    private final RealmModel realm;
    private final ResourceServer resourceServer;
    private final ResourceSetResource resourceManager;

    @Context
    private Authorization authorizationManager;

    @Context
    private KeycloakSession keycloakSession;
    private final Identity identity;

    public ResourceService(RealmModel realm, ResourceServer resourceServer, Identity identity, ResourceSetResource resourceManager) {
        this.realm = realm;
        this.identity = identity;
        this.resourceServer = resourceServer;
        this.resourceManager = resourceManager;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response create(UmaResourceRepresentation umaResource) {
        checkResourceServerSettings();
        ResourceRepresentation resource = toResourceRepresentation(umaResource);
        Response response = this.resourceManager.create(resource);

        if (response.getEntity() instanceof ResourceRepresentation) {
            return Response.status(Response.Status.CREATED).entity(toUmaRepresentation((ResourceRepresentation) response.getEntity())).build();
        }

        return response;
    }

    @Path("/{id}")
    @DELETE
    public Response delete(@PathParam("id") String id) {
        checkResourceServerSettings();
        return this.resourceManager.delete(id);
    }

    @DELETE
    public Response deleteAll() {
        checkResourceServerSettings();
        this.findAll().forEach(this::delete);
        return Response.noContent().build();
    }

    @Path("/{id}")
    @GET
    @Produces("application/json")
    public RegistrationResponse findById(@PathParam("id") String id) {
        Response response = this.resourceManager.findById(id);
        UmaResourceRepresentation resource = toUmaRepresentation((ResourceRepresentation) response.getEntity());

        if (resource == null) {
            throw new ErrorResponseException("not_found", "Resource with id [" + id + "] not found.", Response.Status.NOT_FOUND);
        }

        return new RegistrationResponse(resource);
    }

    @GET
    @Produces("application/json")
    public Set<String> findAll() {
        Response response = this.resourceManager.findAll();
        List<ResourceRepresentation> resources = (List<ResourceRepresentation>) response.getEntity();
        return resources.stream().map(ResourceRepresentation::getId).collect(Collectors.toSet());
    }

    @Path("/search")
    @GET
    @Produces("application/json")
    public Set<String> search(@QueryParam("filter") String filter) {
        Set<ResourceRepresentation> resources = new HashSet<>();

        if (filter != null) {
            for (String currentFilter : filter.split("&")) {
                String[] parts = currentFilter.split("=");
                String filterType = parts[0];
                final String filterValue;

                if (parts.length > 1) {
                    filterValue = parts[1];
                } else {
                    filterValue = null;
                }

                if ("name".equals(filterType)) {
                    resources.addAll(this.authorizationManager.getStoreFactory().getResourceStore().findByResourceServer(this.resourceServer.getId()).stream().filter(description -> filterValue == null || filterValue.equals(description.getName())).collect(Collectors.toSet()).stream()
                            .map(resource -> Models.toRepresentation(resource, this.resourceServer, this.authorizationManager, this.realm, this.keycloakSession))
                            .collect(Collectors.toList()));
                } else if ("type".equals(filterType)) {
                    resources.addAll(this.authorizationManager.getStoreFactory().getResourceStore().findByResourceServer(this.resourceServer.getId()).stream().filter(description -> filterValue == null || filterValue.equals(description.getType())).collect(Collectors.toSet()).stream()
                            .map(resource -> Models.toRepresentation(resource, this.resourceServer, this.authorizationManager, this.realm, this.keycloakSession))
                            .collect(Collectors.toList()));
                } else if ("uri".equals(filterType)) {
                    resources.addAll(this.authorizationManager.getStoreFactory().getResourceStore().findByResourceServer(this.resourceServer.getId()).stream().filter(description -> filterValue == null || filterValue.equals(description.getUri())).collect(Collectors.toSet()).stream()
                            .map(resource -> Models.toRepresentation(resource, this.resourceServer, this.authorizationManager, this.realm, this.keycloakSession))
                            .collect(Collectors.toList()));
                } else if ("owner".equals(filterType)) {
                    resources.addAll(this.authorizationManager.getStoreFactory().getResourceStore().findByResourceServer(this.resourceServer.getId()).stream().filter(description -> filterValue == null || filterValue.equals(description.getOwner())).collect(Collectors.toSet()).stream()
                            .map(resource -> Models.toRepresentation(resource, this.resourceServer, this.authorizationManager, this.realm, this.keycloakSession))
                            .collect(Collectors.toList()));
                }
            }
        } else {
            resources = this.authorizationManager.getStoreFactory().getResourceStore().findByOwner(identity.getId()).stream()
                    .map(resource -> Models.toRepresentation(resource, this.resourceServer, this.authorizationManager, this.realm, this.keycloakSession))
                    .collect(Collectors.toSet());
        }

        return resources.stream()
                .map(ResourceRepresentation::getId)
                .collect(Collectors.toSet());
    }

    private ResourceRepresentation toResourceRepresentation(UmaResourceRepresentation umaResource) {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setId(umaResource.getId());
        resource.setIconUri(umaResource.getIconUri());
        resource.setName(umaResource.getName());
        resource.setUri(umaResource.getUri());
        resource.setType(umaResource.getType());

        ResourceOwnerRepresentation owner = new ResourceOwnerRepresentation();
        String ownerId = umaResource.getOwner();

        if (ownerId == null) {
            ownerId = this.identity.getId();
        }

        owner.setId(ownerId);
        resource.setOwner(owner);

        resource.setScopes(umaResource.getScopes().stream().map(representation -> {
            ScopeRepresentation scopeRepresentation = new ScopeRepresentation();

            scopeRepresentation.setId(representation.getId());
            scopeRepresentation.setName(representation.getName());
            scopeRepresentation.setIconUri(representation.getIconUri());

            return scopeRepresentation;
        }).collect(Collectors.toSet()));

        return resource;
    }

    private UmaResourceRepresentation toUmaRepresentation(ResourceRepresentation representation) {
        if (representation == null) {
            return null;
        }

        UmaResourceRepresentation resource = new UmaResourceRepresentation();

        resource.setId(representation.getId());
        resource.setIconUri(representation.getIconUri());
        resource.setName(representation.getName());
        resource.setUri(representation.getUri());
        resource.setType(representation.getType());

        if (representation.getOwner() != null) {
            resource.setOwner(representation.getOwner().getId());
        }

        resource.setScopes(representation.getScopes().stream().map(scopeRepresentation -> {
            UmaScopeRepresentation umaScopeRep = new UmaScopeRepresentation();
            umaScopeRep.setId(scopeRepresentation.getId());
            umaScopeRep.setName(scopeRepresentation.getName());
            umaScopeRep.setIconUri(scopeRepresentation.getIconUri());
            return umaScopeRep;
        }).collect(Collectors.toSet()));

        return resource;
    }

    private void checkResourceServerSettings() {
        if (!this.resourceServer.isAllowRemoteResourceManagement()) {
            throw new ErrorResponseException("not_supported", "Remote management is disabled.", Response.Status.BAD_REQUEST);
        }
    }
}