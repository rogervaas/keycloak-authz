package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.permission.ResourcePermission;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Evaluation {

    ResourcePermission getPermission();
    EvaluationContext getContext();

    void grant();
    boolean isGranted();
}
