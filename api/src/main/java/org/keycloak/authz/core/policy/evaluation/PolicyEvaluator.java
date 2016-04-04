package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.Decision;

/**
 * <p>A {@link PolicyEvaluator} evaluates authorization policies based on a bounded or unbounded number of permissions, sending
 * the results to one or more {@link Decision} points through the methods defined in that interface.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyEvaluator {

    /**
     * Starts the evaluation of the configured authorization policies.
     *
     * @param decision a {@link Decision} point to where notifications events will be delivered during the evaluation
     */
    void evaluate(ResourcePermission permission, EvaluationContext executionContext, Decision decision);
}
