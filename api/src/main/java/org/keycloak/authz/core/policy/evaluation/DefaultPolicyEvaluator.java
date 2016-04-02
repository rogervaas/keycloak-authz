package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.policy.Decision;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultPolicyEvaluator implements PolicyEvaluator {

    private final EvaluationContext evaluationContex;
    private final PolicyStore policyStore;
    private Map<String, PolicyProviderFactory> policyProviders = new HashMap<>();
    private Executor decideOn = Runnable::run;
    private CompletableFuture<?> future = CompletableFuture.completedFuture(null);

    public DefaultPolicyEvaluator(EvaluationContext evaluationContext, PolicyStore policyStore, List<PolicyProviderFactory> providerFactories) {
        this.evaluationContex = evaluationContext;
        this.policyStore = policyStore;

        for (PolicyProviderFactory provider : providerFactories) {
            this.policyProviders.put(provider.getType(), provider);
        }
    }

    @Override
    public void evaluate(Decision decision) {
        this.future = CompletableFuture.allOf(this.future, CompletableFuture.runAsync(() -> {
            for (;;) {
                ResourcePermission permission = evaluationContex.getPermissions().get();

                if (permission == null) {
                    break;
                }

                evaluate(permission, createDecisionConsumer(permission, decision));
            }
        }, this.decideOn).whenCompleteAsync((BiConsumer<Object, Throwable>) (o, cause) -> {
            if (cause == null) {
                decision.onComplete();
            } else {
                decision.onError(cause);
            }
        }, this.decideOn));
    }

    public Consumer<Policy> createDecisionConsumer(ResourcePermission permission, Decision decision) {
        return (parentPolicy) -> {
            if (hasRequestedScopes(permission, parentPolicy)) {
                for (Policy associatedPolicy : parentPolicy.getAssociatedPolicies()) {
                    PolicyProvider policyProvider = policyProviders.get(associatedPolicy.getType()).create(associatedPolicy);

                    if (policyProvider == null) {
                        throw new RuntimeException("Unknown parentPolicy provider for type [" + associatedPolicy.getType() + "].");
                    }

                    DecisionWrapper decisionWrapper = new DecisionWrapper(decision);
                    Evaluation evaluation = new Evaluation(permission, evaluationContex, parentPolicy, associatedPolicy, decisionWrapper);

                    try {
                        policyProvider.evaluate(evaluation);
                    } catch (Throwable cause) {
                        cause.printStackTrace();
                    }

                    if (decisionWrapper.hasStatus(DecisionWrapper.Status.UNKOWN)) {
                        decisionWrapper.onDeny(evaluation);
                    }
                }
            }
        };
    }

    private void evaluate(ResourcePermission permission, Consumer<Policy> consumer) {
        Resource resource = permission.getResource();

        if (resource != null) {
            List<? extends Policy> resourcePolicies = this.policyStore.findByResource(resource.getId());

            if (!resourcePolicies.isEmpty()) {
                resourcePolicies.forEach(consumer);
            }

            if (resource.getType() != null) {
                this.policyStore.findByResourceType(resource.getType()).forEach(consumer);
            }

            if (permission.getScopes().isEmpty() && !resource.getScopes().isEmpty()) {
                this.policyStore.findByScopeName(resource.getScopes().stream().map(Scope::getName).collect(Collectors.toList())).forEach(consumer);
            }
        }

        if (!permission.getScopes().isEmpty()) {
            this.policyStore.findByScopeName(permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList())).forEach(consumer);
        }
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
