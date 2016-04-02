package org.keycloak.authz.policy.provider.drools;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.Advice;
import org.keycloak.authz.core.policy.evaluation.Evaluation;
import org.keycloak.authz.core.policy.evaluation.EvaluationContext;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class EvaluationWrapper extends Evaluation {

    private Evaluation delegate;

    EvaluationWrapper(Evaluation delegate) {
        super(delegate.getPermission(), delegate.getContext());
        this.delegate = delegate;
    }

    @Override
    public ResourcePermission getPermission() {
        return delegate.getPermission();
    }

    @Override
    public EvaluationContext getContext() {
        return new EvaluationContextWrapper(delegate.getContext());
    }

    @Override
    public void grant() {
        delegate.grant();
    }

    @Override
    public void deny() {
        delegate.deny();
    }

    @Override
    public void grantWithAdvices(List<Advice> advices) {
        delegate.grantWithAdvices(advices);
    }

    @Override
    public Policy getPolicy() {
        return delegate.getPolicy();
    }

    @Override
    public Policy getParentPolicy() {
        return delegate.getParentPolicy();
    }
}
