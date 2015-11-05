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
package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.ResourceServer.PolicyEnforcementMode;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.EvaluationResult.PolicyResult.Status;
import org.keycloak.authz.core.policy.spi.PolicyProvider;
import org.keycloak.authz.core.policy.spi.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultPolicyManager implements PolicyManager {

    private Map<String, PolicyProviderFactory> providers = new HashMap<>();
    private PolicyStore policyStore;

    public DefaultPolicyManager(PolicyStore policyStore, List<PolicyProviderFactory> providerFactories) {
        this.policyStore = policyStore;

        for (PolicyProviderFactory provider : providerFactories) {
            this.providers.put(provider.getType(), provider);
        }
    }

    @Override
    public List<EvaluationResult> evaluate(EvaluationContext context) {
        List<EvaluationResult> results = new ArrayList<>();

        for (ResourcePermission permission : context.getAllPermissions()) {
            EvaluationResult result = new EvaluationResult(permission);

            results.add(result);

            Map<Policy, EvaluationResult.PolicyResult> toEvaluate = getEvaluationPolicies(permission, result);
            ResourceServer resourceServer = permission.getResource().getResourceServer();

            if (PolicyEnforcementMode.DISABLED.equals(resourceServer.getPolicyEnforcementMode())) {
                result.setStatus(Status.GRANTED);
                continue;
            }

            if (toEvaluate.isEmpty()) {
                if (PolicyEnforcementMode.ENFORCING.equals(resourceServer.getPolicyEnforcementMode())) {
                    result.setStatus(Status.DENIED);
                    continue;
                }
            }

            toEvaluate.forEach((policy, policyResult) -> {
                Map<Policy, Boolean> decisions = new HashMap<>();

                for (Policy associatedPolicy : policy.getAssociatedPolicies()) {
                    PolicyProvider provider = getProviderFactory(associatedPolicy.getType()).create(associatedPolicy);

                    if (provider != null) {
                        Evaluation evaluation = new Evaluation() {
                            @Override
                            public ResourcePermission getPermission() {
                                return permission;
                            }

                            @Override
                            public EvaluationContext getContext() {
                                return context;
                            }

                            @Override
                            public void grant() {
                                policyResult.policy(associatedPolicy).status(Status.GRANTED);
                                decisions.put(associatedPolicy, true);
                            }

                            @Override
                            public boolean isGranted() {
                                return decisions.getOrDefault(associatedPolicy, false);
                            }
                        };

                        provider.evaluate(evaluation);

                        if (!evaluation.isGranted()) {
                            policyResult.policy(associatedPolicy).status(Status.DENIED);
                            decisions.put(associatedPolicy, false);
                        }
                    }
                }

                if (isPermit(policy, decisions)) {
                    policyResult.status(Status.GRANTED);
                } else {
                    policyResult.status(Status.DENIED);
                }
            });

            if (toEvaluate.values().stream()
                    .filter(policyResult -> Status.DENIED.equals(policyResult.getStatus())).count() > 0) {
                result.setStatus(Status.DENIED);
            } else {
                result.setStatus(Status.GRANTED);
            }
        }

        if (results.stream().filter(evaluationResult -> Status.DENIED.equals(evaluationResult.getStatus())).count() == 0) {
            context.grant();
        }

        return results;
    }

    @Override
    public List<PolicyProviderFactory> getProviderFactories() {
        return this.providers.values().stream().collect(Collectors.toList());
    }

    @Override
    public void dispose() {
        this.providers.values().forEach(PolicyProviderFactory::dispose);
    }

    @Override
    public PolicyProviderFactory getProviderFactory(String type) {
        return this.providers.get(type);
    }

    private Map<Policy, EvaluationResult.PolicyResult> getEvaluationPolicies(ResourcePermission permission, EvaluationResult result) {
        Map<Policy, EvaluationResult.PolicyResult> toEvaluate = new HashMap<>();

        for (Policy policy : getMatchingPolicies(permission)) {
            EvaluationResult.PolicyResult policyResult = result.policy(policy);

            if (hasRequestedScopes(permission, policy, policyResult)) {
                continue;
            }

            toEvaluate.put(policy, policyResult);
        }
        return toEvaluate;
    }

    private boolean isPermit(Policy policy, Map<Policy, Boolean> decisions) {
        Collection<Boolean> values = decisions.values();

        int grantCount = 0;
        int denyCount = values.size();

        for (Boolean decision : values) {
            if (decision) {
                grantCount++;
                denyCount--;
            }
        }

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

    private boolean hasRequestedScopes(final ResourcePermission permission, final Policy policy, final EvaluationResult.PolicyResult policyResult) {
        boolean scopeMismatch = false;

        if (!permission.getScopes().isEmpty()) {
            if (!policy.getScopes().isEmpty()) {
                boolean hasScope = false;

                for (Scope givenScope : policy.getScopes()) {
                    boolean hasGivenScope = false;
                    for (Scope scope : permission.getScopes()) {
                        if (givenScope.getId().equals(scope.getId())) {
                            hasGivenScope = true;
                            break;
                        }
                    }
                    if (hasGivenScope) {
                        hasScope = true;
                        break;
                    }
                }

                if (!hasScope) {
                    policyResult.status(Status.SKIPPED_WITH_SCOPES_MISMATCH);
                    scopeMismatch = true;
                }
            }
        }

        return scopeMismatch;
    }

    private Set<Policy> getMatchingPolicies( ResourcePermission permission) {
        Set<Policy> policies = new HashSet<>();

        policies.addAll(this.policyStore.findByResource(permission.getResource().getId()));
        policies.addAll(this.policyStore.findByResourceType(permission.getResource().getType()));
        policies.addAll(this.policyStore.findByScopeName(permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList())));

        return policies;
    }
}
