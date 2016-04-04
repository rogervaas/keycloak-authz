package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.Advice;
import org.keycloak.authz.core.policy.Decision;
import org.keycloak.authz.core.policy.provider.PolicyProvider;

import java.util.Collections;
import java.util.List;

/**
 * <p>An {@link Evaluation} is mainly used by {@link PolicyProvider} in order to evaluate a single
 * and specific {@link ResourcePermission} against the configured policies.
 *
 * <p>Differently than {@link EvaluationContext}, the {@link Evaluation} has narrow scope, specific for a single {@link ResourcePermission}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Evaluation {

    private final ResourcePermission permission;
    private final ExecutionContext executionContext;
    private final Decision decision;
    private final Policy policy;
    private final Policy parentPolicy;
    private List<Advice> advices = Collections.emptyList();
    private Decision.Effect effect;

    public Evaluation(ResourcePermission permission, ExecutionContext executionContext, Policy parentPolicy, Policy policy, Decision decision) {
        this.permission = permission;
        this.executionContext = executionContext;
        this.parentPolicy = parentPolicy;
        this.policy = policy;
        this.decision = decision;
    }

    /**
     * Returns the {@link ResourcePermission} to be evaluated.
     *
     * @return the permission to be evaluated
     */
    public ResourcePermission getPermission() {
        return this.permission;
    }

    /**
     * Returns the {@link EvaluationContext}. Which provides access to the whole evaluation runtime context.
     *
     * @return the evaluation context
     */
    public ExecutionContext getContext() {
        return this.executionContext;
    }

    /**
     * Grants all the requested permissions to the caller.
     */
    public void grant() {
        this.effect = Decision.Effect.PERMIT;
        this.decision.onDecision(this, this.effect);
    }

    public void deny() {
        this.effect = Decision.Effect.DENY;
        this.decision.onDecision(this, this.effect);
    }

    public void grantWithAdvices(List<Advice> advices) {
        this.advices = advices;
        grant();
    }

    public Policy getPolicy() {
        return this.policy;
    }

    public Policy getParentPolicy() {
        return this.parentPolicy;
    }

    void denyIfNoEffect() {
        if (this.effect == null) {
            this.decision.onDecision(this, Decision.Effect.DENY);
        }
    }
}
