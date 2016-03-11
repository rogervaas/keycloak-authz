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
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.policy.EvaluationResult;
import org.keycloak.authz.core.policy.ExecutionContext;
import org.keycloak.authz.core.policy.PolicyManager;
import org.keycloak.authz.server.admin.resource.representation.PolicyEvaluationRequest;
import org.keycloak.authz.server.admin.resource.representation.PolicyEvaluationResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEvaluateResource {

    private final RealmModel realm;

    @Context
    private Authorization authorizationManager;

    @Context
    private KeycloakSession keycloakSession;

    private final ResourceServer resourceServer;

    public PolicyEvaluateResource(RealmModel realm, ResourceServer resourceServer) {
        this.realm = realm;
        this.resourceServer = resourceServer;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response evaluate(PolicyEvaluationRequest representation) {
        PolicyManager manager = this.authorizationManager.getPolicyManager();
        List<ResourcePermission> permissions = new ArrayList<>();

        representation.getResources().forEach(resource -> {
            Set<String> givenScopes = resource.getScopes();

            if (givenScopes == null) {
                givenScopes = new HashSet();
            }

            List<Scope> scopes = givenScopes.stream().map(scopeName -> authorizationManager.getStoreFactory().getScopeStore().findByName(scopeName))
                    .collect(Collectors.toList());

            if (resource.getId() != null) {
                Resource resourceModel = authorizationManager.getStoreFactory().getResourceStore().findById(resource.getId());
                permissions.add(new ResourcePermission(resourceModel, scopes));
            } else if (resource.getType() != null) {
                authorizationManager.getStoreFactory().getResourceStore().findByType(resource.getType()).forEach(resource1 -> permissions.add(new ResourcePermission(resource1, scopes)));
            }
        });

        DefaultEvaluationContext context = new DefaultEvaluationContext(null, this.realm, permissions, new ExecutionContext() {
            @Override
            public Map<String, List<String>> getAttributes() {
                Map<String, String> givenAttributes = representation.getContext().get("attributes");

                return givenAttributes.entrySet().stream()
                        .collect(Collectors.toMap(
                                (Function<Map.Entry<String, String>, String>) Map.Entry<String, String>::getKey,
                                (Function<Map.Entry<String, String>, List<String>>) entry -> {
                                    String entryValue = entry.getValue();

                                    if (entryValue == null) {
                                        return Collections.emptyList();
                                    }

                                    List<String> attributes = new ArrayList();

                                    for (String value : entryValue.split(",")) {
                                        attributes.add(value);
                                    }

                                    return attributes;
                                }));
            }
        }) {
            @Override
            public Identity getIdentity() {
                return new Identity() {
                    @Override
                    public String getId() {
                        return representation.getUserId();
                    }

                    @Override
                    public Map<String, List<String>> getAttributes() {
                        HashMap<String, List<String>> attributes = new HashMap<>();
                        UserModel userModel = keycloakSession.users().getUserById(getId(), realm);

                        if (userModel != null) {
                            Set<RoleModel> roleMappings = userModel.getRoleMappings();
                            List<String> roles = roleMappings.stream().map(RoleModel::getName).collect(Collectors.toList());
                            attributes.put("roles", roles);
                        }

                        Map<String, String> givenAttributes = representation.getContext().get("attributes");

                        if (givenAttributes != null) {
                            givenAttributes.forEach(new BiConsumer<String, String>() {
                                @Override
                                public void accept(String key, String value) {
                                    attributes.put(key, Arrays.asList(value));
                                }
                            });
                        }

                        return attributes;
                    }
                };
            }
        };

        List<EvaluationResult> results = manager.evaluate(context);

        return Response.ok(PolicyEvaluationResponse.build(this.realm, context, results, this.resourceServer, this.authorizationManager, this.keycloakSession)).build();
    }
}
