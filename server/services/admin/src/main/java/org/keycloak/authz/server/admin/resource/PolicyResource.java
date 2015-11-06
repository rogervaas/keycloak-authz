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

import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.server.admin.resource.representation.PolicyProviderRepresentation;
import org.keycloak.authz.server.admin.resource.representation.PolicyRepresentation;
import org.keycloak.authz.server.admin.resource.util.Models;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

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
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.keycloak.authz.server.admin.resource.util.Models.toRepresentation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyResource {

    private final RealmModel realm;
    private final ResourceServer resourceServer;
    private final Map<String, PolicyProviderAdminResource> policyTypeResources = new HashMap<>();

    @Context
    private Authorization authorizationManager;

    @Context
    private KeycloakSession keycloakSession;

    public PolicyResource(RealmModel realm, ResourceServer resourceServer) {
        this.realm = realm;
        this.resourceServer = resourceServer;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response create(PolicyRepresentation representation) {
        Policy policy = Models.toModel(representation, this.resourceServer, this.authorizationManager);

        updateResources(policy);
        updateAssociatedPolicies(policy);
        updateScopes(policy);

        this.authorizationManager.getStoreFactory().policy().save(policy);

        PolicyProviderAdminResource resource = getPolicyProviderAdminResource(policy.getType());

        if (resource != null) {
            resource.create(policy);
        }

        representation.setId(policy.getId());

        return Response.status(Response.Status.CREATED).entity(representation).build();
    }

    @Path("{id}")
    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    public Response update(@PathParam("id") String id, PolicyRepresentation representation) {
        Policy policy = authorizationManager.getStoreFactory().policy().findById(representation.getId());

        if (policy == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        policy.setName(representation.getName());
        policy.setDescription(representation.getDescription());
        policy.setConfig(representation.getConfig());
        policy.setDecisionStrategy(representation.getDecisionStrategy());

        updateResources(policy);
        updateAssociatedPolicies(policy);
        updateScopes(policy);

        PolicyProviderAdminResource resource = getPolicyProviderAdminResource(policy.getType());

        if (resource != null) {
            resource.update(policy);
        }

        this.authorizationManager.getStoreFactory().policy().save(policy);

        return Response.status(Response.Status.CREATED).build();
    }

    @Path("{id}")
    @DELETE
    public Response delete(@PathParam("id") String id) {
        Policy policy = authorizationManager.getStoreFactory().policy().findById(id);

        if (policy == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        PolicyProviderAdminResource resource = getPolicyProviderAdminResource(policy.getType());

        if (resource != null) {
            resource.remove(policy);
        }

        this.authorizationManager.getStoreFactory().policy().findDependentPolicies(id).forEach(dependentPolicy -> {
            dependentPolicy.removeAssociatedPolicy(policy);
            this.authorizationManager.getStoreFactory().policy().save(dependentPolicy);
        });

        this.authorizationManager.getStoreFactory().policy().delete(policy.getId());

        return Response.noContent().build();
    }

    @Path("{id}")
    @GET
    @Produces("application/json")
    public Response findById(@PathParam("id") String id) {
        Policy model = authorizationManager.getStoreFactory().policy().findById(id);

        if (model == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        return Response.ok(toRepresentation(model, this.authorizationManager)).build();
    }

    @GET
    @Produces("application/json")
    public Response findAll() {
        return Response.ok(
                authorizationManager.getStoreFactory().policy().findByServer(resourceServer.getId()).stream()
                        .map((Function<Policy, PolicyRepresentation>) policy -> {
                            return Models.toRepresentation(policy, this.authorizationManager);
                        })
                        .collect(Collectors.toList()))
                .build();
    }

    @Path("providers")
    @GET
    @Produces("application/json")
    public Response findPolicyProviders() {
        return Response.ok(
                authorizationManager.getPolicyManager().getProviderFactories().stream()
                        .map(provider -> {
                            PolicyProviderRepresentation representation = new PolicyProviderRepresentation();

                            representation.setName(provider.getName());
                            representation.setGroup(provider.getGroup());
                            representation.setType(provider.getType());

                            return representation;
                        })
                        .collect(Collectors.toList()))
                .build();
    }

    @Path("evaluate")
    public PolicyEvaluateResource getPolicyEvaluateResource() {
        PolicyEvaluateResource resource = new PolicyEvaluateResource(this.realm, this.resourceServer);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }

    @Path("{policyType}")
    public Object getPolicyTypeResource(@PathParam("policyType") String policyType) {
        return getPolicyProviderAdminResource(policyType);
    }

    private PolicyProviderAdminResource getPolicyProviderAdminResource(final @PathParam("policyType") String policyType) {
        if (!this.policyTypeResources.containsKey(policyType)) {
            for (PolicyProviderAdminResource loadedProvider : ServiceLoader.load(PolicyProviderAdminResource.class, getClass().getClassLoader())) {
                this.policyTypeResources.put(loadedProvider.getType(), loadedProvider);
            }
        }

        PolicyProviderAdminResource resource = this.policyTypeResources.get(policyType);

        if (resource != null) {
            ResteasyProviderFactory.getInstance().injectProperties(resource);
            resource.init(this.resourceServer);
        }


        return resource;
    }

    private void updateScopes(Policy policy) {
        String scopes = policy.getConfig().get("scopes");
        if (scopes != null) {
            String[] scopeIds;

            try {
                scopeIds = new ObjectMapper().readValue(scopes, String[].class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            for (String scopeId : scopeIds) {
                boolean hasScope = false;

                for (Scope scopeModel : new HashSet<>(policy.getScopes())) {
                    if (scopeModel.getId().equals(scopeId)) {
                        hasScope = true;
                    }
                }
                if (!hasScope) {
                    policy.addScope(authorizationManager.getStoreFactory().scope().findById(scopeId));
                }
            }

            for (Scope scopeModel : new HashSet<>(policy.getScopes())) {
                boolean hasScope = false;

                for (String scopeId : scopeIds) {
                    if (scopeModel.getId().equals(scopeId)) {
                        hasScope = true;
                    }
                }
                if (!hasScope) {
                    policy.removeScope(scopeModel);
                }
            }
        }
    }

    private void updateAssociatedPolicies(Policy policy) {
        String policies = policy.getConfig().get("applyPolicies");
        if (policies != null) {
            String[] policyIds;

            try {
                policyIds = new ObjectMapper().readValue(policies, String[].class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            for (String policyId : policyIds) {
                boolean hasPolicy = false;

                for (Policy policyModel : new HashSet<>(policy.getAssociatedPolicies())) {
                    if (policyModel.getId().equals(policyId)) {
                        hasPolicy = true;
                    }
                }
                if (!hasPolicy) {
                    policy.addAssociatedPolicy(authorizationManager.getStoreFactory().policy().findById(policyId));
                }
            }

            for (Policy policyModel : new HashSet<>(policy.getAssociatedPolicies())) {
                boolean hasPolicy = false;

                for (String policyId : policyIds) {
                    if (policyModel.getId().equals(policyId)) {
                        hasPolicy = true;
                    }
                }
                if (!hasPolicy) {
                    policy.removeAssociatedPolicy(policyModel);
                }
            }
        }
    }

    private void updateResources(Policy policy) {
        String resources = policy.getConfig().get("resources");
        if (resources != null) {
            String[] resourceIds;
            try {
                resourceIds = new ObjectMapper().readValue(resources, String[].class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            for (String resourceId : resourceIds) {
                boolean hasResource = false;
                for (Resource resourceModel : new HashSet<Resource>(policy.getResources())) {
                    if (resourceModel.getId().equals(resourceId)) {
                        hasResource = true;
                    }
                }
                if (!hasResource && !"".equals(resourceId)) {
                    policy.addResource(authorizationManager.getStoreFactory().resource().findById(resourceId));
                }
            }
            for (Resource resourceModel : new HashSet<Resource>(policy.getResources())) {
                boolean hasResource = false;
                for (String resourceId : resourceIds) {
                    if (resourceModel.getId().equals(resourceId)) {
                        hasResource = true;
                    }
                }
                if (!hasResource) {
                    policy.removeResource(resourceModel);
                }
            }
        }
    }
}
