/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authz.core.policy.evaluation;

import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.Decision;

import java.util.Iterator;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see EvaluationContext
 */
class IterablePermissionPublisher implements PermissionEmitter {

    private final Iterator<ResourcePermission> permissions;
    private final ExecutionContext executionContext;
    private final PolicyEvaluator policyEvaluator;

    IterablePermissionPublisher(Iterator<ResourcePermission> permissions, ExecutionContext executionContext, PolicyEvaluator policyEvaluator) {
        this.permissions = permissions;
        this.executionContext = executionContext;
        this.policyEvaluator = policyEvaluator;
    }

    @Override
    public void evaluate(Decision decision) {
        try {
            forEach(permission -> this.policyEvaluator.evaluate(permission, this.executionContext, decision));
            decision.onComplete();
        } catch (Throwable cause) {
            decision.onError(cause);
        }
    }

    @Override
    public void forEach(Consumer<ResourcePermission> consumer) {
        while (this.permissions.hasNext()) {
            consumer.accept(this.permissions.next());
        }
    }
}
