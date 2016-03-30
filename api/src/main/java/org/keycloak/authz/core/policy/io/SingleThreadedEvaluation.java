package org.keycloak.authz.core.policy.io;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.policy.Evaluation;
import org.keycloak.authz.core.policy.EvaluationContext;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SingleThreadedEvaluation implements PolicyEvaluation {

    private final EvaluationContext evaluationContex;
    private final PolicyStore policyStore;
    private Map<String, PolicyProviderFactory> policyProviders = new HashMap<>();

    public SingleThreadedEvaluation(EvaluationContext evaluationContext, PolicyStore policyStore, List<PolicyProviderFactory> providerFactories) {
        this.evaluationContex = evaluationContext;
        this.policyStore = policyStore;

        for (PolicyProviderFactory provider : providerFactories) {
            this.policyProviders.put(provider.getType(), provider);
        }
    }

    @Override
    public void evaluate(Decision decision) {
        try {
            this.evaluationContex.getAllPermissions().forEach(permission -> getPolicies(permission).stream()
                    .forEach(parentPolicy -> {
                        parentPolicy.getAssociatedPolicies().forEach(policy -> {
                            PolicyProvider policyProvider = policyProviders.get(policy.getType()).create(policy);

                            if (policyProvider == null) {
                                throw new RuntimeException("Unknown policy provider for type [" + policy.getType() + "].");
                            }

                            DecisionWrapper decisionWrapper = new DecisionWrapper(decision);
                            Evaluation evaluation = new Evaluation(permission, evaluationContex, parentPolicy, policy, decisionWrapper);

                            policyProvider.evaluate(evaluation);

                            if (decisionWrapper.hasStatus(DecisionWrapper.Status.UNKOWN)) {
                                decision.onDeny(evaluation);
                            }
                        });
                    }));
            decision.onComplete();
        } catch (Throwable cause) {
            decision.onError(cause);
        }
    }

    private Set<Policy> getPolicies(ResourcePermission permission) {
        Set<Policy> policies = new HashSet<>();

        policies.addAll(permission.getResource().getPolicies());
        policies.addAll(this.policyStore.findByResourceType(permission.getResource().getType()));
        policies.addAll(this.policyStore.findByScopeName(permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList())));

        if (permission.getScopes().isEmpty()) {
            policies.addAll(this.policyStore.findByScopeName(permission.getResource().getScopes().stream().map(Scope::getName).collect(Collectors.toList())));
        }

        return policies.stream().filter(policy -> hasRequestedScopes(permission, policy)).collect(Collectors.toSet());
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
