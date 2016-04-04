package org.keycloak.authz.core;

import org.keycloak.authz.core.policy.evaluation.Evaluation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Decision {

    enum Effect {
        PERMIT,
        DENY
    }

    void onDecision(Evaluation evaluation, Effect effect);

    default void onError(Throwable cause) {
        throw new RuntimeException("Not implemented.", cause);
    }

    default void onComplete() {
    }
}
