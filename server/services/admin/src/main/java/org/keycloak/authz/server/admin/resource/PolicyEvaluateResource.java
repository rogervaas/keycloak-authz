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
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.policy.Evaluation;
import org.keycloak.authz.core.policy.EvaluationResult;
import org.keycloak.authz.core.policy.io.Decision;
import org.keycloak.authz.core.policy.io.SingleThreadedEvaluation;
import org.keycloak.authz.server.admin.resource.representation.PolicyEvaluationRequest;
import org.keycloak.authz.server.admin.resource.representation.PolicyEvaluationResponse;
import org.keycloak.authz.server.services.core.DefaultExecutionContext;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.stream.Collectors;

import static javafx.scene.input.KeyCode.R;

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
            } else {
                permissions.addAll(scopes.stream().map(new Function<Scope, ResourcePermission>() {
                    @Override
                    public ResourcePermission apply(Scope scope) {
                        return new ResourcePermission(null, Arrays.asList(scope));
                    }
                }).collect(Collectors.toList()));
            }
        });

        DefaultEvaluationContext context = new DefaultEvaluationContext(createIdentity(representation), this.realm, permissions, new DefaultExecutionContext(this.keycloakSession, this.realm) {
            @Override
            public Map<String, List<String>> getAttributes() {
                Map<String, List<String>> attributes = super.getAttributes();

                Map<String, String> givenAttributes = representation.getContext().get("attributes");

                givenAttributes.forEach((key, entryValue) -> {
                    if (entryValue != null) {
                        List<String> values = new ArrayList();

                        for (String value : entryValue.split(",")) {
                            values.add(value);
                        }

                        attributes.put(key, values);
                    }
                });

                return attributes;
            }
        });

        SingleThreadedEvaluation evaluation = new SingleThreadedEvaluation(context, this.authorizationManager.getStoreFactory().getPolicyStore(), this.authorizationManager.getPolicyManager().getProviderFactories());
        Map<ResourcePermission, EvaluationResult> results = new HashMap();

        evaluation.evaluate(new Decision() {
            @Override
            public void onGrant(Evaluation evaluation) {
                results.computeIfAbsent(evaluation.getPermission(), EvaluationResult::new).policy(evaluation.getParentPolicy()).policy(evaluation.getPolicy()).setStatus(EvaluationResult.PolicyResult.Status.GRANTED);
            }

            @Override
            public void onDeny(Evaluation evaluation) {
                results.computeIfAbsent(evaluation.getPermission(), EvaluationResult::new).policy(evaluation.getParentPolicy()).policy(evaluation.getPolicy()).setStatus(EvaluationResult.PolicyResult.Status.DENIED);
            }

            @Override
            public void onComplete() {
                for (EvaluationResult result : results.values()) {
                    for (EvaluationResult.PolicyResult policyResult : result.getResults()) {
                        if (isGranted(policyResult)) {
                            policyResult.setStatus(EvaluationResult.PolicyResult.Status.GRANTED);
                        } else {
                            policyResult.setStatus(EvaluationResult.PolicyResult.Status.DENIED);
                        }
                    }

                    if (result.getResults().stream()
                            .filter(policyResult -> EvaluationResult.PolicyResult.Status.DENIED.equals(policyResult.getStatus())).count() > 0) {
                        result.setStatus(EvaluationResult.PolicyResult.Status.DENIED);
                    } else {
                        result.setStatus(EvaluationResult.PolicyResult.Status.GRANTED);
                    }
                }
            }

            @Override
            public void onError(Throwable cause) {
            }

            private boolean isGranted(EvaluationResult.PolicyResult policyResult) {
                List<EvaluationResult.PolicyResult> values = policyResult.getAssociatedPolicies();

                int grantCount = 0;
                int denyCount = values.size();

                for (EvaluationResult.PolicyResult decision : values) {
                    if (decision.getStatus().equals(EvaluationResult.PolicyResult.Status.GRANTED)) {
                        grantCount++;
                        denyCount--;
                    }
                }

                Policy policy = policyResult.getPolicy();
                Policy.DecisionStrategy decisionStrategy = policy.getDecisionStrategy();

                if (decisionStrategy == null) {
                    decisionStrategy = Policy.DecisionStrategy.UNANIMOUS;
                }

                if (Policy.DecisionStrategy.AFFIRMATIVE.equals(decisionStrategy) && grantCount > 0) {
                    return true;
                } else if (Policy.DecisionStrategy.UNANIMOUS.equals(decisionStrategy) && denyCount == 0) {
                    return true;
                } else if (Policy.DecisionStrategy.CONSENSUS.equals(decisionStrategy)) {
                    if (grantCount > denyCount) {
                        return true;
                    }
                }

                return false;
            }
        });

        return Response.ok(PolicyEvaluationResponse.build(realm, context, results.values().stream().collect(Collectors.toList()), resourceServer, authorizationManager, keycloakSession)).build();
    }

    public Identity createIdentity(PolicyEvaluationRequest representation) {
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
}
