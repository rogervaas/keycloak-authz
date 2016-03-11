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
package org.keycloak.authz.core.policy;

import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;

import java.util.List;

/**
 * The {@link PolicyManager} acts as a facade for policy evaluation and access to the configured policy providers.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyManager {

    /**
     * Evaluates all registered policies accordingly with the given {@link EvaluationContext}.
     *
     * @param context the context that will be used to base policy decisions
     * @return a list of {@link EvaluationResult} with all decisions taken during the evaluation
     */
    List<EvaluationResult> evaluate(EvaluationContext context);

    /**
     * Returns a list with all registered {@link PolicyProviderFactory}.
     *
     * @return a list containing the registered policy provider factories
     */
    List<PolicyProviderFactory> getProviderFactories();

    /**
     * Disposes of this instance and releases any system resources that it is using.
     */
    void dispose();
}
