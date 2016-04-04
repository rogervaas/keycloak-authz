package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Evaluator {

    private final Authorization authorization;
    private final List<PolicyProviderFactory> policyProviderFactories;
    private final DefaultPolicyEvaluator policyEvaluator;

    public Evaluator(Authorization authorization, List<PolicyProviderFactory> policyProviderFactories, DefaultPolicyEvaluator policyEvaluator) {
        this.authorization = authorization;
        this.policyProviderFactories = policyProviderFactories;
        this.policyEvaluator = policyEvaluator;
    }

    public EvaluationContext from(List<ResourcePermission> permissions, ExecutionContext executionContext) {
        return createEvaluationContext(permissions, executionContext);
    }

    public EvaluationContext from(Supplier<ResourcePermission> supplier, ExecutionContext executionContext) {
        return createEvaluationContext(supplier, executionContext);
    }

    public EvaluationContext schedule(List<ResourcePermission> permissions, ExecutionContext executionContext, Executor scheduler) {
        return new ScheduledPermissionPublisher(createEvaluationContext(permissions, executionContext), scheduler);
    }

    public EvaluationContext schedule(Supplier<ResourcePermission> permissions, ExecutionContext executionContext, Executor scheduler) {
        return new ScheduledPermissionPublisher(createEvaluationContext(permissions, executionContext), scheduler);
    }

    private IterablePermissionPublisher createEvaluationContext(List<ResourcePermission> permissions, ExecutionContext executionContext) {
        return new IterablePermissionPublisher(permissions.iterator(), executionContext, this.policyEvaluator);
    }

    private SupplierPermissionPublisher createEvaluationContext(Supplier<ResourcePermission> permissions, ExecutionContext executionContext) {
        return new SupplierPermissionPublisher(permissions, executionContext, this.policyEvaluator);
    }
}
