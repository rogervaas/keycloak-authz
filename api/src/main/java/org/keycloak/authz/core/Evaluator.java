package org.keycloak.authz.core;

import org.keycloak.authz.core.policy.evaluation.DefaultPolicyEvaluator;
import org.keycloak.authz.core.policy.evaluation.EvaluationContext;
import org.keycloak.authz.core.policy.evaluation.PolicyEvaluator;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.StoreFactory;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Evaluator {

    private final StoreFactory storeFactory;
    private final List<PolicyProviderFactory> policyProviderFactories;

    Evaluator(StoreFactory storeFactory, List<PolicyProviderFactory> policyProviderFactories) {
        this.storeFactory = storeFactory;
        this.policyProviderFactories = policyProviderFactories;
    }

    public PolicyEvaluator from(EvaluationContext evaluationContext) {
        return new DefaultPolicyEvaluator(evaluationContext, this.storeFactory.getPolicyStore(), this.policyProviderFactories);
    }
}
