package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.ResourceServer.PolicyEnforcementMode;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
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
        ResourceServer resourceServer = permission.getResourceServer();

        if (PolicyEnforcementMode.DISABLED.equals(resourceServer.getPolicyEnforcementMode())) {
            createEvaluation(permission, executionContext, decision, null, null).grant();
            return;
        }

        PolicyStore policyStore = this.authorization.getStoreFactory().getPolicyStore();
        AtomicInteger policiesCount = new AtomicInteger(0);
        Consumer<Policy> consumer = createDecisionConsumer(permission, executionContext, decision, policiesCount);
        Resource resource = permission.getResource();

        if (resource != null) {
            List<? extends Policy> resourcePolicies = policyStore.findByResource(resource.getId());

            if (!resourcePolicies.isEmpty()) {
                resourcePolicies.forEach(consumer);
            }

            if (resource.getType() != null) {
                policyStore.findByResourceType(resource.getType(), resourceServer.getId()).forEach(consumer);
            }

            if (permission.getScopes().isEmpty() && !resource.getScopes().isEmpty()) {
                policyStore.findByScopeName(resource.getScopes().stream().map(Scope::getName).collect(Collectors.toList()), resourceServer.getId()).forEach(consumer);
            }
        }

        if (!permission.getScopes().isEmpty()) {
            policyStore.findByScopeName(permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList()), resourceServer.getId()).forEach(consumer);
        }

        if (PolicyEnforcementMode.PERMISSIVE.equals(resourceServer.getPolicyEnforcementMode()) && policiesCount.get() == 0) {
            createEvaluation(permission, executionContext, decision, null, null).grant();
        }
    }

    private  Consumer<Policy> createDecisionConsumer(ResourcePermission permission, EvaluationContext executionContext, Decision decision, AtomicInteger policiesCount) {
        return (parentPolicy) -> {
            if (hasRequestedScopes(permission, parentPolicy)) {
                for (Policy associatedPolicy : parentPolicy.getAssociatedPolicies()) {
                    PolicyProvider policyProvider = policyProviders.get(associatedPolicy.getType()).create(associatedPolicy);

                    if (policyProvider == null) {
                        throw new RuntimeException("Unknown parentPolicy provider for type [" + associatedPolicy.getType() + "].");
                    }

                    Evaluation evaluation = createEvaluation(permission, executionContext, decision, parentPolicy, associatedPolicy);

                    policyProvider.evaluate(evaluation);
                    evaluation.denyIfNoEffect();

                    policiesCount.incrementAndGet();
                }
            }
        };
    }

    private Evaluation createEvaluation(ResourcePermission permission, EvaluationContext executionContext, Decision decision, Policy parentPolicy, Policy associatedPolicy) {
        return new Evaluation(permission, executionContext, parentPolicy, associatedPolicy, decision);
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
