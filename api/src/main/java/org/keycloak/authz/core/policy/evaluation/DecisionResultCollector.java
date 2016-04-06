package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.permission.ResourcePermission;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class DecisionResultCollector implements Decision {

    private Map<ResourcePermission, Result> results = new HashMap();

    @Override
    public void onDecision(Evaluation evaluation) {
        if (evaluation.getParentPolicy() != null) {
            results.computeIfAbsent(evaluation.getPermission(), Result::new).policy(evaluation.getParentPolicy()).policy(evaluation.getPolicy()).setStatus(evaluation.getEffect());
        } else {
            results.computeIfAbsent(evaluation.getPermission(), Result::new).setStatus(evaluation.getEffect());
        }
    }

    @Override
    public void onComplete() {
        for (Result result : results.values()) {
            for (Result.PolicyResult policyResult : result.getResults()) {
                if (isGranted(policyResult)) {
                    policyResult.setStatus(Effect.PERMIT);
                } else {
                    policyResult.setStatus(Effect.DENY);
                }
            }

            if (result.getResults().stream()
                    .filter(policyResult -> Effect.DENY.equals(policyResult.getStatus())).count() > 0) {
                result.setStatus(Effect.DENY);
            } else {
                result.setStatus(Effect.PERMIT);
            }
        }

        onComplete(results.values().stream().collect(Collectors.toList()));
    }

    protected abstract void onComplete(List<Result> results);

    private boolean isGranted(Result.PolicyResult policyResult) {
        List<Result.PolicyResult> values = policyResult.getAssociatedPolicies();

        int grantCount = 0;
        int denyCount = policyResult.getPolicy().getAssociatedPolicies().size();

        for (Result.PolicyResult decision : values) {
            if (decision.getStatus().equals(Effect.PERMIT)) {
                grantCount++;
                denyCount--;
            }
        }

        Policy policy = policyResult.getPolicy();
        Policy.DecisionStrategy decisionStrategy = policy.getDecisionStrategy();

        if (decisionStrategy == null) {
            decisionStrategy = Policy.DecisionStrategy.UNANIMOUS;
        }

        if (Policy.DecisionStrategy.AFFIRMATIVE.equals(decisionStrategy) && grantCount > 0) {
            return true;
        } else if (Policy.DecisionStrategy.UNANIMOUS.equals(decisionStrategy) && denyCount == 0) {
            return true;
        } else if (Policy.DecisionStrategy.CONSENSUS.equals(decisionStrategy)) {
            if (grantCount > denyCount) {
                return true;
            }
        }

        return false;
    }
}
