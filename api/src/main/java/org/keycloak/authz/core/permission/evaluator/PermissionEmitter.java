package org.keycloak.authz.core.permission.evaluator;

import org.keycloak.authz.core.permission.ResourcePermission;

import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PermissionEmitter extends PermissionEvaluator {

    void forEach(Consumer<ResourcePermission> permission);

}
