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

import org.jboss.resteasy.plugins.providers.multipart.InputPart;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.server.admin.resource.representation.PolicyRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ResourceOwnerRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ResourceRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ResourceServerRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ScopeRepresentation;
import org.keycloak.authz.server.admin.resource.util.Models;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponse;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceServerResource {

    private final RealmModel realm;

    @Context
    private Authorization authorizationManager;

    @Context
    private KeycloakSession keycloakSession;

    public ResourceServerResource(RealmModel realm) {
        this.realm = realm;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response create(ResourceServerRepresentation server) {
        ResourceServer client = this.authorizationManager.getStoreFactory().getResourceServerStore().findByClient(server.getClientId());

        if (client != null) {
            ClientModel clientModel = this.keycloakSession.realms().getClientById(server.getClientId(), this.realm);
            return ErrorResponse.error("Client [" + clientModel.getClientId() + "] already registered as a resource server.", Response.Status.BAD_REQUEST);
        }

        ResourceServer model = Models.toModel(server, this.authorizationManager, this.realm);

        this.authorizationManager.getStoreFactory().getResourceServerStore().save(model);

        ResourceServerRepresentation newServer = new ResourceServerRepresentation();

        newServer.setId(model.getId());

        return Response.status(Response.Status.CREATED).entity(newServer).build();
    }

    @Path("{id}")
    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response update(@PathParam("id") String id, ResourceServerRepresentation server) {
        ResourceServer model = this.authorizationManager.getStoreFactory().getResourceServerStore().findById(server.getId());

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        model.setAllowRemoteResourceManagement(server.isAllowRemoteResourceManagement());
        model.setAllowRemotePolicyManagement(server.isAllowRemotePolicyManagement());
        model.setPolicyEnforcementMode(server.getPolicyEnforcementMode());

        this.authorizationManager.getStoreFactory().getResourceServerStore().save(model);

        return Response.noContent().build();
    }

    @Path("{id}")
    @DELETE
    public Response delete(@PathParam("id") String id) {
        this.authorizationManager.getStoreFactory().getResourceStore().findByResourceServer(id).forEach(resource -> this.authorizationManager.getStoreFactory().getResourceStore().delete(resource.getId()));
        this.authorizationManager.getStoreFactory().getScopeStore().findByResourceServer(id).forEach(scope -> this.authorizationManager.getStoreFactory().getScopeStore().delete(scope.getId()));
        this.authorizationManager.getStoreFactory().getPolicyStore().findByResourceServer(id).forEach(scope -> this.authorizationManager.getStoreFactory().getPolicyStore().remove(scope.getId()));
        this.authorizationManager.getStoreFactory().getResourceServerStore().delete(id);
        return Response.noContent().build();
    }

    @Path("{id}")
    @GET
    @Produces("application/json")
    public Response findById(@PathParam("id") String id) {
        ResourceServer model = this.authorizationManager.getStoreFactory().getResourceServerStore().findById(id);

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        return Response.ok(Models.toRepresentation(model, this.realm)).build();
    }

    @GET
    @Produces("application/json")
    public Response findAll() {
        return Response.ok(
                this.authorizationManager.getStoreFactory().getResourceServerStore().findByRealm(this.realm.getId()).stream()
                        .map(resourceServer -> Models.toRepresentation(resourceServer, this.realm))
                        .collect(Collectors.toList()))
                .build();
    }

    @Path("{id}/settings")
    @GET
    @Produces("application/json")
    public Response exportSettings(@PathParam("id") String id) {
        ResourceServer model = this.authorizationManager.getStoreFactory().getResourceServerStore().findById(id);

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        ResourceServerRepresentation settings = Models.toRepresentation(model, this.realm);

        settings.setId(null);
        settings.setName(null);
        settings.setClientId(this.realm.getClientById(settings.getClientId()).getClientId());

        List<ResourceRepresentation> resources = this.authorizationManager.getStoreFactory().getResourceStore().findByResourceServer(model.getId())
                .stream().map(resource -> {
                    ResourceRepresentation rep = Models.toRepresentation(resource, model, authorizationManager, realm, keycloakSession);

                    rep.getOwner().setId(null);
                    rep.setId(null);
                    rep.setPolicies(null);
                    rep.getScopes().forEach(scopeRepresentation -> {
                        scopeRepresentation.setId(null);
                        scopeRepresentation.setIconUri(null);
                    });

                    return rep;
                }).collect(Collectors.toList());

        settings.setResources(resources);

        List<PolicyRepresentation> policies = this.authorizationManager.getStoreFactory().getPolicyStore().findByResourceServer(model.getId())
                .stream().map(policy -> {
                    PolicyRepresentation rep = Models.toRepresentation(policy, authorizationManager);

                    rep.setId(null);
                    rep.setDependentPolicies(null);

                    Map<String, String> config = rep.getConfig();

                    String roles = config.get("roles");

                    if (roles != null && !roles.isEmpty()) {
                        roles = roles.replace("[", "");
                        roles = roles.replace("]", "");

                        if (!roles.isEmpty()) {
                            String roleNames = "";

                            for (String role : roles.split(",")) {
                                if (!roleNames.isEmpty()) {
                                    roleNames = roleNames + ",";
                                }

                                role = role.replace("\"", "");

                                roleNames = roleNames + "\"" + realm.getRoleById(role).getName() + "\"";
                            }

                            config.put("roles", "[" + roleNames + "]");
                        }
                    }

                    String users = config.get("users");

                    if (users != null) {
                        users = users.replace("[", "");
                        users = users.replace("]", "");

                        if (!users.isEmpty()) {
                            String userNames = "";

                            for (String user : users.split(",")) {
                                if (!userNames.isEmpty()) {
                                    userNames =  userNames + ",";
                                }

                                user = user.replace("\"", "");

                                userNames = userNames + "\"" + keycloakSession.users().getUserById(user, realm).getUsername() + "\"";
                            }

                            config.put("users", "[" + userNames + "]");
                        }
                    }

                    String scopes = config.get("scopes");

                    if (scopes != null && !scopes.isEmpty()) {
                        scopes = scopes.replace("[", "");
                        scopes = scopes.replace("]", "");

                        if (!scopes.isEmpty()) {
                            String scopeNames = "";

                            for (String scope : scopes.split(",")) {
                                if (!scopeNames.isEmpty()) {
                                    scopeNames =  scopeNames + ",";
                                }

                                scope = scope.replace("\"", "");

                                scopeNames = scopeNames + "\"" + authorizationManager.getStoreFactory().getScopeStore().findById(scope).getName() + "\"";
                            }

                            config.put("scopes", "[" + scopeNames + "]");
                        }
                    }

                    String policyResources = config.get("resources");

                    if (policyResources != null && !policyResources.isEmpty()) {
                        policyResources = policyResources.replace("[", "");
                        policyResources = policyResources.replace("]", "");

                        if (!policyResources.isEmpty()) {
                            String resourceNames = "";

                            for (String resource : policyResources.split(",")) {
                                if (!resourceNames.isEmpty()) {
                                    resourceNames =  resourceNames + ",";
                                }

                                resource = resource.replace("\"", "");

                                resourceNames = resourceNames + "\"" + authorizationManager.getStoreFactory().getResourceStore().findById(resource).getName() + "\"";
                            }

                            config.put("resources", "[" + resourceNames + "]");
                        }
                    }

                    String applyPolicies = config.get("applyPolicies");

                    if (applyPolicies != null && !applyPolicies.isEmpty()) {
                        applyPolicies = applyPolicies.replace("[", "");
                        applyPolicies = applyPolicies.replace("]", "");

                        if (!applyPolicies.isEmpty()) {
                            String policyNames = "";

                            for (String pId : applyPolicies.split(",")) {
                                if (!policyNames.isEmpty()) {
                                    policyNames = policyNames + ",";
                                }

                                pId = pId.replace("\"", "");

                                policyNames = policyNames + "\"" + authorizationManager.getStoreFactory().getPolicyStore().findById(pId).getName() + "\"";
                            }

                            config.put("applyPolicies", "[" + policyNames + "]");
                        }
                    }

                    return rep;
                }).collect(Collectors.toList());

        settings.setPolicies(policies);

        List<ScopeRepresentation> scopes = this.authorizationManager.getStoreFactory().getScopeStore().findByResourceServer(model.getId()).stream().map(new Function<Scope, ScopeRepresentation>() {
            @Override
            public ScopeRepresentation apply(Scope scope) {
                ScopeRepresentation rep = Models.toRepresentation(scope);

                rep.setId(null);

                rep.getPolicies().forEach(policyRepresentation -> {
                    policyRepresentation.setId(null);
                    policyRepresentation.setConfig(null);
                    policyRepresentation.setType(null);
                    policyRepresentation.setDecisionStrategy(null);
                    policyRepresentation.setDescription(null);
                    policyRepresentation.setDependentPolicies(null);
                });

                return rep;
            }
        }).collect(Collectors.toList());

        settings.setScopes(scopes);

        return Response.ok(settings).build();
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response importSettings(@Context final UriInfo uriInfo, MultipartFormDataInput input) throws IOException {
        Map<String, List<InputPart>> uploadForm = input.getFormDataMap();
        List<InputPart> inputParts = uploadForm.get("file");
        ResourceServerRepresentation rep = null;
        Response response = null;

        for (InputPart inputPart : inputParts) {
            // inputPart.getBody doesn't work as content-type is wrong, and inputPart.setMediaType is not supported on AS7 (RestEasy 2.3.2.Final)
            rep = JsonSerialization.readValue(inputPart.getBodyAsString(), ResourceServerRepresentation.class);

            ClientModel client = this.realm.getClientByClientId(rep.getClientId());
            String clientId = client.getId();

            rep.setClientId(clientId);

            response = create(rep);

            ResourceServer resourceServer = this.authorizationManager.getStoreFactory().getResourceServerStore().findByClient(clientId);

            ScopeResource scopeResource = new ScopeResource(resourceServer);

            ResteasyProviderFactory.getInstance().injectProperties(scopeResource);

            rep.getScopes().forEach(new Consumer<ScopeRepresentation>() {
                @Override
                public void accept(ScopeRepresentation scopeRepresentation) {
                    scopeResource.create(scopeRepresentation);
                }
            });

            ResourceSetResource resourceSetResource = new ResourceSetResource(this.realm, resourceServer, this.authorizationManager, this.keycloakSession);

            rep.getResources().forEach(new Consumer<ResourceRepresentation>() {
                @Override
                public void accept(ResourceRepresentation resourceRepresentation) {
                    ResourceOwnerRepresentation owner = resourceRepresentation.getOwner();

                    owner.setId(resourceServer.getClientId());

                    UserModel user = keycloakSession.users().getUserByUsername(owner.getName(), realm);

                    if (user != null) {
                        owner.setId(user.getId());
                    }

                    resourceSetResource.create(resourceRepresentation);
                }
            });

            PolicyResource policyResource = new PolicyResource(this.realm, resourceServer);

            ResteasyProviderFactory.getInstance().injectProperties(policyResource);

            rep.getPolicies().forEach(new Consumer<PolicyRepresentation>() {
                @Override
                public void accept(PolicyRepresentation policyRepresentation) {
                    Map<String, String> config = policyRepresentation.getConfig();

                    String roles = config.get("roles");

                    if (roles != null && !roles.isEmpty()) {
                        roles = roles.replace("[", "");
                        roles = roles.replace("]", "");

                        if (!roles.isEmpty()) {
                            String roleNames = "";

                            for (String role : roles.split(",")) {
                                if (!roleNames.isEmpty()) {
                                    roleNames = roleNames + ",";
                                }

                                role = role.replace("\"", "");

                                roleNames = roleNames + "\"" + realm.getRole(role).getId() + "\"";
                            }

                            config.put("roles", "[" + roleNames + "]");
                        }
                    }

                    String users = config.get("users");

                    if (users != null) {
                        users = users.replace("[", "");
                        users = users.replace("]", "");

                        if (!users.isEmpty()) {
                            String userNames = "";

                            for (String user : users.split(",")) {
                                if (!userNames.isEmpty()) {
                                    userNames =  userNames + ",";
                                }

                                user = user.replace("\"", "");

                                userNames = userNames + "\"" + keycloakSession.users().getUserByUsername(user, realm).getId() + "\"";
                            }

                            config.put("users", "[" + userNames + "]");
                        }
                    }

                    String scopes = config.get("scopes");

                    if (scopes != null && !scopes.isEmpty()) {
                        scopes = scopes.replace("[", "");
                        scopes = scopes.replace("]", "");

                        if (!scopes.isEmpty()) {
                            String scopeNames = "";

                            for (String scope : scopes.split(",")) {
                                if (!scopeNames.isEmpty()) {
                                    scopeNames =  scopeNames + ",";
                                }

                                scope = scope.replace("\"", "");

                                scopeNames = scopeNames + "\"" + authorizationManager.getStoreFactory().getScopeStore().findByName(scope).getId() + "\"";
                            }

                            config.put("scopes", "[" + scopeNames + "]");
                        }
                    }

                    String policyResources = config.get("resources");

                    if (policyResources != null && !policyResources.isEmpty()) {
                        policyResources = policyResources.replace("[", "");
                        policyResources = policyResources.replace("]", "");

                        if (!policyResources.isEmpty()) {
                            String resourceNames = "";

                            for (String resource : policyResources.split(",")) {
                                if (!resourceNames.isEmpty()) {
                                    resourceNames =  resourceNames + ",";
                                }

                                resource = resource.replace("\"", "");

                                if ("".equals(resource)) {
                                    continue;
                                }

                                resourceNames = resourceNames + "\"" + authorizationManager.getStoreFactory().getResourceStore().findByName(resource).getId() + "\"";
                            }

                            config.put("resources", "[" + resourceNames + "]");
                        }
                    }

                    String applyPolicies = config.get("applyPolicies");

                    if (applyPolicies != null && !applyPolicies.isEmpty()) {
                        applyPolicies = applyPolicies.replace("[", "");
                        applyPolicies = applyPolicies.replace("]", "");

                        if (!applyPolicies.isEmpty()) {
                            String policyNames = "";

                            for (String pId : applyPolicies.split(",")) {
                                if (!policyNames.isEmpty()) {
                                    policyNames = policyNames + ",";
                                }

                                pId = pId.replace("\"", "");

                                policyNames = policyNames + "\"" + authorizationManager.getStoreFactory().getPolicyStore().findByName(pId).getId() + "\"";
                            }

                            config.put("applyPolicies", "[" + policyNames + "]");
                        }
                    }

                    policyResource.create(policyRepresentation);
                }
            });
        }

        return Response.noContent().build();
    }

    @Path("{id}/resource")
    public ResourceSetResource getResourceSetResource(@PathParam("id") String id) {
        ResourceSetResource resource = new ResourceSetResource(this.realm, this.authorizationManager.getStoreFactory().getResourceServerStore().findById(id), this.authorizationManager, this.keycloakSession);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("{id}/scope")
    public ScopeResource getScopeResource(@PathParam("id") String id) {
        ScopeResource resource = new ScopeResource(this.authorizationManager.getStoreFactory().getResourceServerStore().findById(id));

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("{id}/policy")
    public PolicyResource getPolicyResource(@PathParam("id") String id) {
        PolicyResource resource = new PolicyResource(this.realm, this.authorizationManager.getStoreFactory().getResourceServerStore().findById(id));

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }
}
