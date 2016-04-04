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
package org.keycloak.authz.core;

import org.keycloak.authz.core.attribute.Attributes;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.models.RealmModel;

/**
 * This interface serves as a bridge between the policy evaluation runtime and the environment in which it is running. When evaluating
 * policies, this interface can be used to query information from the execution environment/context and enrich decisions.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface EvaluationContext {

    /**
     * Returns the {@link Identity} that represents an entity (person or non-person) to which the permissions must be granted, or not.
     *
     * @return the identity to which the permissions must be granted, or not
     */
    Identity getIdentity();

    /**
     * Returns the {@link RealmModel} representing the security domain in which the evaluation must be done.
     *
     * @return the realm representing the security domain in which the evaluation must be done
     */
    RealmModel getRealm();

    /**
     * Returns all attributes within the current execution and runtime environment.
     *
     * @return the attributes within the current execution and runtime environment
     */
    Attributes getAttributes();
}
