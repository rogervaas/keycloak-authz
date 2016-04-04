package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Evaluator {

    private final Authorization authorization;
    private final List<PolicyProviderFactory> policyProviderFactories;

    public Evaluator(Authorization authorization, List<PolicyProviderFactory> policyProviderFactories) {
        this.authorization = authorization;
        this.policyProviderFactories = policyProviderFactories;
    }

    public PolicyEvaluator from(List<ResourcePermission> permissions, ExecutionContext executionContext) {
        return new DefaultPolicyEvaluator(createEvaluationContext(permissions, executionContext), this.authorization, this.policyProviderFactories, Runnable::run);
    }

    public PolicyEvaluator from(Supplier<ResourcePermission> supplier, ExecutionContext executionContext) {
        return new DefaultPolicyEvaluator(createEvaluationContext(supplier, executionContext), this.authorization, this.policyProviderFactories, Executors.newSingleThreadExecutor());
    }

    public PolicyEvaluator schedule(List<ResourcePermission> permissions, ExecutionContext executionContext, Executor scheduler) {
        return new DefaultPolicyEvaluator(createEvaluationContext(permissions, executionContext), this.authorization, this.policyProviderFactories, scheduler);
    }

    public IterablePermissionProducer createEvaluationContext(List<ResourcePermission> permissions, ExecutionContext executionContext) {
        return new IterablePermissionProducer(permissions.iterator(), executionContext);
    }

    public SupplierPermissionProducer createEvaluationContext(Supplier<ResourcePermission> permissions, ExecutionContext executionContext) {
        return new SupplierPermissionProducer(permissions, executionContext);
    }
}
