package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourcePermission;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EvaluationResult {

    private final ResourcePermission permission;
    private List<PolicyResult> results = new ArrayList<>();
    private PolicyResult.Status status;

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

    public void setStatus(final PolicyResult.Status status) {
        this.status = status;
    }

    public PolicyResult.Status getStatus() {
        return status;
    }

    public static class PolicyResult {

        private final Policy policy;
        private List<PolicyResult> associatedPolicies = new ArrayList<>();
        private Status status;

        public PolicyResult(Policy policy) {
            this.policy = policy;
        }

        public PolicyResult status(Status status) {
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

        public Status getStatus() {
            return status;
        }

        public void setStatus(final Status status) {
            this.status = status;
        }

        public enum Status {
            GRANTED,
            DENIED,
            SKIPPED_WITH_SCOPES_MISMATCH;
        }
    }
}
