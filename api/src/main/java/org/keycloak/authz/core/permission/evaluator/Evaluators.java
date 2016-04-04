package org.keycloak.authz.core.permission.evaluator;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.evaluation.DefaultPolicyEvaluator;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Evaluators {

    private final Authorization authorization;
    private final List<PolicyProviderFactory> policyProviderFactories;
    private final DefaultPolicyEvaluator policyEvaluator;

    public Evaluators(Authorization authorization, List<PolicyProviderFactory> policyProviderFactories, DefaultPolicyEvaluator policyEvaluator) {
        this.authorization = authorization;
        this.policyProviderFactories = policyProviderFactories;
        this.policyEvaluator = policyEvaluator;
    }

    public PermissionEvaluator from(List<ResourcePermission> permissions, EvaluationContext executionContext) {
        return createEvaluationContext(permissions, executionContext);
    }

    public PermissionEvaluator from(Supplier<ResourcePermission> supplier, EvaluationContext executionContext) {
        return createEvaluationContext(supplier, executionContext);
    }

    public PermissionEvaluator schedule(List<ResourcePermission> permissions, EvaluationContext executionContext, Executor scheduler) {
        return new ScheduledPermissionEvaluator(createEvaluationContext(permissions, executionContext), scheduler);
    }

    public PermissionEvaluator schedule(Supplier<ResourcePermission> permissions, EvaluationContext executionContext, Executor scheduler) {
        return new ScheduledPermissionEvaluator(createEvaluationContext(permissions, executionContext), scheduler);
    }

    private IterablePermissionEvaluator createEvaluationContext(List<ResourcePermission> permissions, EvaluationContext executionContext) {
        return new IterablePermissionEvaluator(permissions.iterator(), executionContext, this.policyEvaluator);
    }

    private SupplierPermissionEvaluator createEvaluationContext(Supplier<ResourcePermission> permissions, EvaluationContext executionContext) {
        return new SupplierPermissionEvaluator(permissions, executionContext, this.policyEvaluator);
    }
}
