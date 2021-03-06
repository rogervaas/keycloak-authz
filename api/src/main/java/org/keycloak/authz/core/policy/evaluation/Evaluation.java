package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.permission.evaluator.PermissionEvaluator;
import org.keycloak.authz.core.policy.provider.PolicyProvider;

/**
 * <p>An {@link Evaluation} is mainly used by {@link PolicyProvider} in order to evaluate a single
 * and specific {@link ResourcePermission} against the configured policies.
 *
 * <p>Differently than {@link PermissionEvaluator}, the {@link Evaluation} has narrow scope, specific for a single {@link ResourcePermission}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Evaluation {

    private final ResourcePermission permission;
    private final EvaluationContext executionContext;
    private final Decision decision;
    private final Policy policy;
    private final Policy parentPolicy;
    private Decision.Effect effect;

    public Evaluation(ResourcePermission permission, EvaluationContext executionContext, Policy parentPolicy, Policy policy, Decision decision) {
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
     * Returns the {@link PermissionEvaluator}. Which provides access to the whole evaluation runtime context.
     *
     * @return the evaluation context
     */
    public EvaluationContext getContext() {
        return this.executionContext;
    }

    /**
     * Grants all the requested permissions to the caller.
     */
    public void grant() {
        if (policy != null && Policy.Logic.NEGATIVE.equals(policy.getLogic())) {
            this.effect = Decision.Effect.DENY;
        } else {
            this.effect = Decision.Effect.PERMIT;
        }

        this.decision.onDecision(this);
    }

    public void deny() {
        if (policy != null && Policy.Logic.NEGATIVE.equals(policy.getLogic())) {
            this.effect = Decision.Effect.PERMIT;
        } else {
            this.effect = Decision.Effect.DENY;
        }

        this.decision.onDecision(this);
    }

    public Policy getPolicy() {
        return this.policy;
    }

    public Policy getParentPolicy() {
        return this.parentPolicy;
    }

    public Decision.Effect getEffect() {
        return effect;
    }

    void denyIfNoEffect() {
        if (this.effect == null) {
            deny();
        }
    }
}
