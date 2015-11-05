package org.keycloak.authz.core.policy;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.permission.ResourcePermission;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EvaluationResult {

    private final ResourcePermission permission;
    private List<PolicyResult> policies = new ArrayList<>();
    private PolicyResult.Status status;

    public EvaluationResult(ResourcePermission permission) {
        this.permission = permission;
    }

    public ResourcePermission getPermission() {
        return permission;
    }

    public List<PolicyResult> getPolicies() {
        return policies;
    }

    public PolicyResult policy(Policy policy) {
        PolicyResult policyResult = new PolicyResult(policy);

        this.policies.add(policyResult);

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
            PolicyResult policyResult = new PolicyResult(policy);

            this.associatedPolicies.add(policyResult);

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
