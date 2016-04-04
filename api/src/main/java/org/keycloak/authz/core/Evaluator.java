package org.keycloak.authz.core;

import org.keycloak.authz.core.policy.evaluation.DefaultPolicyEvaluator;
import org.keycloak.authz.core.policy.evaluation.EvaluationContext;
import org.keycloak.authz.core.policy.evaluation.PolicyEvaluator;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Evaluator {

    private final Authorization authorization;
    private final List<PolicyProviderFactory> policyProviderFactories;

    Evaluator(Authorization authorization, List<PolicyProviderFactory> policyProviderFactories) {
        this.authorization = authorization;
        this.policyProviderFactories = policyProviderFactories;
    }

    public PolicyEvaluator from(EvaluationContext evaluationContext) {
        return new DefaultPolicyEvaluator(evaluationContext, this.authorization, this.policyProviderFactories, Executors.newSingleThreadExecutor());
    }

    public PolicyEvaluator schedule(EvaluationContext evaluationContext, Executor executor) {
        return new DefaultPolicyEvaluator(evaluationContext, this.authorization, this.policyProviderFactories, executor);
    }
}
