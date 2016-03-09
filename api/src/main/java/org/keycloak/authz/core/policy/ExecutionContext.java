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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * This interface serves as a bridge between the policy evaluation runtime and the environment in which it is running. When evaluating
 * policies, this interface can be used to query information from the execution environment/context and enrich decisions.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface ExecutionContext {

    ExecutionContext EMPTY = Collections::emptyMap;

    Map<String, List<String>> getAttributes();

    default boolean hasAttribute(String name, String... values) {
        return getAttributes().entrySet().stream()
                .filter(entry -> entry.getKey().equals(name))
                .filter(entry -> entry.getValue().containsAll(Arrays.asList(values))).findFirst().isPresent();
    }

}
