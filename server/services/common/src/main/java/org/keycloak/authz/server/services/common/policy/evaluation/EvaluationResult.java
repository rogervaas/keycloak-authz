package org.keycloak.authz.server.services.common.policy.evaluation;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.Decision;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EvaluationResult {

    private final ResourcePermission permission;
    private List<PolicyResult> results = new ArrayList<>();
    private Decision.Effect status;

    public EvaluationResult(ResourcePermission permission) {
        this.permission = permission;
    }

    public ResourcePermission getPermission() {
        return permission;
    }

    public List<PolicyResult> getResults() {
        return results;
    }

    public PolicyResult policy(Policy policy) {
        for (PolicyResult result : this.results) {
            if (result.getPolicy().equals(policy)) {
                return result;
            }
        }

        PolicyResult policyResult = new PolicyResult(policy);

        this.results.add(policyResult);

        return policyResult;
    }

    public void setStatus(final Decision.Effect status) {
        this.status = status;
    }

    public Decision.Effect getStatus() {
        return status;
    }

    public boolean anyDenial() {
        return anyDenial(this.results);
    }

    private boolean anyDenial(List<PolicyResult> result) {
        return result.stream().anyMatch(new Predicate<PolicyResult>() {
            @Override
            public boolean test(PolicyResult policyResult) {
                if (Decision.Effect.DENY.equals(policyResult.getStatus()) && !policyResult.getPolicy().getAssociatedPolicies().isEmpty()) {
                    return true;
                }

                return anyDenial(policyResult.getAssociatedPolicies());
            }
        });
    }

    public static class PolicyResult {

        private final Policy policy;
        private List<PolicyResult> associatedPolicies = new ArrayList<>();
        private Decision.Effect status;

        public PolicyResult(Policy policy) {
            this.policy = policy;
        }

        public PolicyResult status(Decision.Effect status) {
            this.status = status;
            return this;
        }

        public PolicyResult policy(Policy policy) {
            return getPolicy(policy, this.associatedPolicies);
        }

        private PolicyResult getPolicy(Policy policy, List<PolicyResult> results) {
            for (PolicyResult result : results) {
                if (result.getPolicy().equals(policy)) {
                    return result;
                }
            }

            PolicyResult policyResult = new PolicyResult(policy);

            results.add(policyResult);

            return policyResult;
        }

        public Policy getPolicy() {
            return policy;
        }

        public List<PolicyResult> getAssociatedPolicies() {
            return associatedPolicies;
        }

        public void setAssociatedPolicies(final List<PolicyResult> associatedPolicies) {
            this.associatedPolicies = associatedPolicies;
        }

        public Decision.Effect getStatus() {
            return status;
        }

        public void setStatus(final Decision.Effect status) {
            this.status = status;
        }
    }
}
