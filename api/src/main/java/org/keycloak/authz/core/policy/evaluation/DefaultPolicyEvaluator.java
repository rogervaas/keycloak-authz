package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultPolicyEvaluator implements PolicyEvaluator {

    private final Authorization authorization;
    private Map<String, PolicyProviderFactory> policyProviders = new HashMap<>();

    public DefaultPolicyEvaluator(Authorization authorization) {
        this.authorization = authorization;

        for (PolicyProviderFactory provider : this.authorization.getProviderFactories()) {
            this.policyProviders.put(provider.getType(), provider);
        }
    }

    @Override
    public void evaluate(ResourcePermission permission, EvaluationContext executionContext, Decision decision) {
        PolicyStore policyStore = this.authorization.getStoreFactory().getPolicyStore();
        Resource resource = permission.getResource();
        Consumer<Policy> consumer = createDecisionConsumer(permission, executionContext, decision);

        if (resource != null) {
            List<? extends Policy> resourcePolicies = policyStore.findByResource(resource.getId());

            if (!resourcePolicies.isEmpty()) {
                resourcePolicies.forEach(consumer);
            }

            if (resource.getType() != null) {
                policyStore.findByResourceType(resource.getType()).forEach(consumer);
            }

            if (permission.getScopes().isEmpty() && !resource.getScopes().isEmpty()) {
                policyStore.findByScopeName(resource.getScopes().stream().map(Scope::getName).collect(Collectors.toList())).forEach(consumer);
            }
        }

        if (!permission.getScopes().isEmpty()) {
            policyStore.findByScopeName(permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList())).forEach(consumer);
        }
    }

    private  Consumer<Policy> createDecisionConsumer(ResourcePermission permission, EvaluationContext executionContext, Decision decision) {
        return (parentPolicy) -> {
            if (hasRequestedScopes(permission, parentPolicy)) {
                for (Policy associatedPolicy : parentPolicy.getAssociatedPolicies()) {
                    PolicyProvider policyProvider = policyProviders.get(associatedPolicy.getType()).create(associatedPolicy);

                    if (policyProvider == null) {
                        throw new RuntimeException("Unknown parentPolicy provider for type [" + associatedPolicy.getType() + "].");
                    }

                    Evaluation evaluation = new Evaluation(permission, executionContext, parentPolicy, associatedPolicy, decision);

                    policyProvider.evaluate(evaluation);

                    evaluation.denyIfNoEffect();
                }
            }
        };
    }

    private boolean hasRequestedScopes(final ResourcePermission permission, final Policy policy) {
        if (permission.getScopes().isEmpty()) {
            return true;
        }

        if (policy.getScopes().isEmpty()) {
            return true;
        }

        boolean hasScope = true;

        for (Scope givenScope : policy.getScopes()) {
            boolean hasGivenScope = false;

            for (Scope scope : permission.getScopes()) {
                if (givenScope.getId().equals(scope.getId())) {
                    hasGivenScope = true;
                    break;
                }
            }

            if (!hasGivenScope) {
                return false;
            }
        }

        return hasScope;
    }
}
