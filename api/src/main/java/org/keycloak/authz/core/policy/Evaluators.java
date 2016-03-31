package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.StoreFactory;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Evaluators {

    private final StoreFactory storeFactory;
    private final List<PolicyProviderFactory> policyProviderFactories;

    public Evaluators(StoreFactory storeFactory, List<PolicyProviderFactory> policyProviderFactories) {
        this.storeFactory = storeFactory;
        this.policyProviderFactories = policyProviderFactories;
    }

    public PolicyEvaluator from(EvaluationContext evaluationContext) {
        return new DefaultPolicyEvaluator(evaluationContext, this.storeFactory.getPolicyStore(), this.policyProviderFactories);
    }
}
