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

import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.models.RealmModel;

import java.util.List;
import java.util.function.Supplier;

/**
 * The evaluation context provides a contract from where policy providers will base their decisions. It represents all the
 * permissions that need to be checked and also provides methods for retrieving information from the runtime environment,
 * which can be used by different access control mechanisms.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface EvaluationContext {

    /**
     * Returns a list with all the requested permissions and that must be evaluated by the underlying policy providers.
     *
     * @return a list with all the permissions that must be evaluated
     */
    Supplier<ResourcePermission> getPermissions();

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
     * Returns the {@link ExecutionContext} from where information from the runtime environment can be obtained and used
     * during the evaluation of policies.
     *
     * @return the execution context from where information from the runtime environment can be obtained
     */
    ExecutionContext getExecutionContext();

    /**
     * Indicates if the requested permissions were granted or not. The permissions are only granted after calling {@link #grant()}.
     *
     * @return true if permissions were granted to the caller. Otherwise it returns false.
     */
    boolean isGranted();
}
