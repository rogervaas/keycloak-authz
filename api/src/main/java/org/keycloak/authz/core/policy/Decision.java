package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.policy.evaluation.Evaluation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Decision {
    void onGrant(Evaluation evaluation);

    default void onDeny(Evaluation evaluation) {
        throw new RuntimeException("Not implemented.");
    }

    default void onError(Throwable cause) {
        throw new RuntimeException("Not implemented.", cause);
    }

    default void onComplete() {

    }
}
