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

import org.keycloak.authz.core.policy.Decision;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see EvaluationContext
 */
class ScheduledPermissionPublisher implements EvaluationContext {

    private final EvaluationContext publisher;
    private final Executor scheduler;

    ScheduledPermissionPublisher(EvaluationContext publisher, Executor scheduler) {
        this.publisher = publisher;
        this.scheduler = scheduler;
    }

    @Override
    public void evaluate(Decision decision) {
        CompletableFuture.runAsync(() -> publisher.evaluate(decision), scheduler);
    }
}
