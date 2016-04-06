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
package org.keycloak.authz.policy.provider.time;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.evaluation.DecisionResultCollector;
import org.keycloak.authz.core.policy.evaluation.Evaluation;
import org.keycloak.authz.core.policy.evaluation.Result;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;

import java.util.List;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AggregatePolicyProvider implements PolicyProvider {

    private final Policy policy;
    private final Authorization authorization;

    public AggregatePolicyProvider(Policy policy, Authorization authorization) {
        this.policy = policy;
        this.authorization = authorization;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        DecisionResultCollector decision = new DecisionResultCollector() {
            @Override
            protected void onComplete(List<Result> results) {
                if (results.isEmpty()) {
                    evaluation.deny();
                } else {
                    Result result = results.iterator().next();

                    if (Effect.PERMIT.equals(result.getEffect())) {
                        evaluation.grant();
                    }
                }
            }
        };

        this.policy.getAssociatedPolicies().forEach(associatedPolicy -> {
            if (associatedPolicy.getType().equals("aggregate")) {
                return;
            }

            PolicyProviderFactory providerFactory = authorization.getProviderFactory(associatedPolicy.getType());
            PolicyProvider policyProvider = providerFactory.create(associatedPolicy);

            policyProvider.evaluate(new Evaluation(evaluation.getPermission(), evaluation.getContext(), policy, associatedPolicy, decision));
        });

        decision.onComplete();
    }
}
