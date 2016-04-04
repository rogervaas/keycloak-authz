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
package org.keycloak.authz.core.permission.evaluator;

import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.permission.ResourcePermission;

/**
 * An {@link PermissionEvaluator} represents a source of {@link ResourcePermission}, responsible for emitting these permissions
 * to a consumer in order to evaluate the authorization policies based on a {@link EvaluationContext}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PermissionEvaluator {

    void evaluate(Decision decision);
}
