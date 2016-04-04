package org.keycloak.authz.server.services.common.policy.evaluation;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.Decision;
import org.keycloak.authz.core.policy.evaluation.Evaluation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DecisionCollector implements Decision {

    private Map<ResourcePermission, EvaluationResult> results = new HashMap();
    private Consumer<List<EvaluationResult>> consumer;

    public DecisionCollector() {
        this(null);
    }

    public DecisionCollector(Consumer<List<EvaluationResult>> consumer) {
        this.consumer = consumer;
    }

    @Override
    public void onDecision(Evaluation evaluation, Effect effect) {
        results.computeIfAbsent(evaluation.getPermission(), EvaluationResult::new).policy(evaluation.getParentPolicy()).policy(evaluation.getPolicy()).setStatus(effect);
    }

    @Override
    public void onComplete() {
        for (EvaluationResult result : results.values()) {
            for (EvaluationResult.PolicyResult policyResult : result.getResults()) {
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

    protected void onComplete(List<EvaluationResult> results) {
        this.consumer.accept(results);
    }

    private boolean isGranted(EvaluationResult.PolicyResult policyResult) {
        List<EvaluationResult.PolicyResult> values = policyResult.getAssociatedPolicies();

        int grantCount = 0;
        int denyCount = values.size();

        for (EvaluationResult.PolicyResult decision : values) {
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
