package org.keycloak.authz.policy.provider.drools;

import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.evaluation.EvaluationContext;
import org.keycloak.authz.core.policy.evaluation.ExecutionContext;
import org.keycloak.authz.policy.provider.drools.api.CallerIdentity;
import org.keycloak.models.RealmModel;

import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class EvaluationContextWrapper implements EvaluationContext {

    private final EvaluationContext delegate;

    EvaluationContextWrapper(EvaluationContext delegate) {
        this.delegate = delegate;
    }

    @Override
    public Supplier<ResourcePermission> getPermissions() {
        return this.delegate.getPermissions();
    }

    @Override
    public Identity getIdentity() {
        return new CallerIdentity(this.delegate.getIdentity());
    }

    @Override
    public RealmModel getRealm() {
        return this.delegate.getRealm();
    }

    @Override
    public ExecutionContext getExecutionContext() {
        return this.delegate.getExecutionContext();
    }

    @Override
    public boolean isGranted() {
        return this.delegate.isGranted();
    }
}
