package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.policy.Decision;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;
import org.keycloak.authz.core.store.StoreFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class DefaultPolicyEvaluator implements PolicyEvaluator {

    private final PermissionProducer evaluationContex;
    private final Authorization authorization;
    private Map<String, PolicyProviderFactory> policyProviders = new HashMap<>();
    private final Executor scheduler;

    DefaultPolicyEvaluator(PermissionProducer permissionProducer, Authorization authorization, List<PolicyProviderFactory> providerFactories, Executor scheduler) {
        this.evaluationContex = permissionProducer;
        this.authorization = authorization;

        for (PolicyProviderFactory provider : providerFactories) {
            this.policyProviders.put(provider.getType(), provider);
        }

        this.scheduler = scheduler;
    }

    @Override
    public void evaluate(Decision decision) {
        createDecisionTask(decision).whenCompleteAsync((aVoid, cause) -> {
            if (cause == null) {
                decision.onComplete();
            } else {
                decision.onError(cause);
            }
        }, this.scheduler);
    }

    private CompletableFuture<Void> createDecisionTask(Decision decision) {
        return CompletableFuture.runAsync(() -> {
            StoreFactory storeFactory = authorization.getStoreFactory();
            PolicyStore policyStore = storeFactory.getPolicyStore();

            evaluationContex.forEach(permission -> {
                Resource resource = permission.getResource();
                Consumer<Policy> consumer = createDecisionConsumer(permission, decision);

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
            });
        }, this.scheduler);
    }

    private  Consumer<Policy> createDecisionConsumer(ResourcePermission permission, Decision decision) {
        return (parentPolicy) -> {
            if (hasRequestedScopes(permission, parentPolicy)) {
                for (Policy associatedPolicy : parentPolicy.getAssociatedPolicies()) {
                    PolicyProvider policyProvider = policyProviders.get(associatedPolicy.getType()).create(associatedPolicy);

                    if (policyProvider == null) {
                        throw new RuntimeException("Unknown parentPolicy provider for type [" + associatedPolicy.getType() + "].");
                    }

                    ExecutionContext executionContext = evaluationContex.getExecutionContext();
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

        if (!policy.getScopes().isEmpty()) {
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
                    hasScope = false;
                    break;
                }
            }

            return hasScope;
        } else {
            return true;
        }
    }
}
