package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.model.ResourcePermission;

import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PermissionEmitter extends EvaluationContext {

    void forEach(Consumer<ResourcePermission> permission);

}
