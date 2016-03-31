package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.policy.Schedulers.Scheduler;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultPolicyEvaluator implements PolicyEvaluator {

    private final EvaluationContext evaluationContex;
    private final PolicyStore policyStore;
    private Map<String, PolicyProviderFactory> policyProviders = new HashMap<>();
    private Scheduler decideOn = Schedulers.parallel();
    private CompletableFuture<?> future = CompletableFuture.completedFuture(null);

    public DefaultPolicyEvaluator(EvaluationContext evaluationContext, PolicyStore policyStore, List<PolicyProviderFactory> providerFactories) {
        this.evaluationContex = evaluationContext;
        this.policyStore = policyStore;

        for (PolicyProviderFactory provider : providerFactories) {
            this.policyProviders.put(provider.getType(), provider);
        }
    }

    public DefaultPolicyEvaluator decideOn(Scheduler scheduler) {
        this.decideOn = scheduler;
        return this;
    }

    @Override
    public void evaluate(Decision decision) {
        try {
            DecisionWrapper decisionWrapper = new DecisionWrapper(decision);

            for (ResourcePermission permission : this.evaluationContex.getAllPermissions()) {
                Consumer<Policy> consumer = parentPolicy -> {
                    for (Policy associatedPolicy : parentPolicy.getAssociatedPolicies()) {
                        PolicyProvider policyProvider = policyProviders.get(associatedPolicy.getType()).create(associatedPolicy);

                        if (policyProvider == null) {
                            throw new RuntimeException("Unknown parentPolicy provider for type [" + associatedPolicy.getType() + "].");
                        }

                        Evaluation evaluation = new Evaluation(permission, evaluationContex, parentPolicy, associatedPolicy, decisionWrapper);

                        policyProvider.evaluate(evaluation);

                        if (decisionWrapper.hasStatus(DecisionWrapper.Status.UNKOWN)) {
                            decision.onDeny(evaluation);
                        }
                    }
                };

                this.future = CompletableFuture.allOf(this.future, CompletableFuture.runAsync(() -> evaluate(permission, consumer), this.decideOn.getExecutor()));
            }

            this.future.whenCompleteAsync((BiConsumer<Object, Throwable>) (o, cause) -> {
                if (cause == null) {
                    decision.onComplete();
                } else {
                    decision.onError(cause);
                }
            });
        } catch (Throwable cause) {
            decision.onError(cause);
        }
    }

    private void evaluate(ResourcePermission permission, Consumer<Policy> consumer) {
        if (permission.getResource() != null) {
            permission.getResource().getPolicies().stream().filter(new Predicate<Policy>() {
                @Override
                public boolean test(Policy policy) {
                    return hasRequestedScopes(permission, policy);
                }
            }).forEach(consumer);

            this.policyStore.findByResourceType(permission.getResource().getType()).stream().filter(new Predicate<Policy>() {
                @Override
                public boolean test(Policy policy) {
                    return hasRequestedScopes(permission, policy);
                }
            }).forEach(consumer);

            if (permission.getScopes().isEmpty()) {
                this.policyStore.findByScopeName(permission.getResource().getScopes().stream().map(Scope::getName).collect(Collectors.toList())).stream().filter(new Predicate<Policy>() {
                    @Override
                    public boolean test(Policy policy) {
                        return hasRequestedScopes(permission, policy);
                    }
                }).forEach(consumer);
            }
        }

        List<Policy> policies = this.policyStore.findByScopeName(permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList()));

        for (Policy policy : policies) {
            if (hasRequestedScopes(permission, policy)) {
                consumer.accept(policy);
            }
        }
    }

    private boolean hasRequestedScopes(final ResourcePermission permission, final Policy policy) {
        boolean scopeMatch = permission.getScopes().isEmpty();

        if (!scopeMatch) {
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
            }
        }

        return scopeMatch;
    }

    private static class DecisionWrapper implements Decision {

        enum Status {
            GRANTED,
            DENIED,
            UNKOWN
        }

        private final Decision delegate;
        private Status status = Status.UNKOWN;

        DecisionWrapper(Decision delegate) {
            this.delegate = delegate;
        }

        @Override
        public void onGrant(Evaluation evaluation) {
            this.status = Status.GRANTED;
            this.delegate.onGrant(evaluation);
        }

        @Override
        public void onDeny(Evaluation evaluation) {
            this.status = Status.DENIED;
            this.delegate.onDeny(evaluation);
        }

        boolean hasStatus(Status status) {
            return this.status.equals(status);
        }
    }
}
