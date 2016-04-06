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
package org.keycloak.authz.core.store;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;

import java.util.List;

/**
 * A {@link PolicyStore} is responsible to manage the persistence of {@link Policy} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyStore {

    /**
     * Creates a new {@link Policy} instance. The new instance is not necessarily persisted though, which may require
     * a call to the {#save} method to actually make it persistent.
     *
     * @param name           the name of the policy
     * @param type           the type of the policy
     * @param resourceServer the resource server to which this policy belongs
     * @return a new instance of {@link Policy}
     */
    Policy create(String name, String type, ResourceServer resourceServer);

    /**
     * Saves a {@link Policy} instance to the underlying persistence mechanism.
     *
     * @param policy the policy instance to save
     */
    void save(Policy policy);

    /**
     * Deletes a policy from the underlying persistence mechanism.
     *
     * @param id the id of the policy to delete
     */
    void remove(String id);

    /**
     * Returns a {@link Policy} with the given <code>id</code>
     *
     * @param id the identifier of the policy
     * @return a policy with the given identifier.
     */
    Policy findById(String id);

    /**
     * Returns a {@link Policy} with the given <code>name</code>
     *
     * @param name             the name of the policy
     * @param resourceServerId the resource server id
     * @return a policy with the given name.
     */
    Policy findByName(String name, String resourceServerId);

    /**
     * Returns a list of {@link Policy} associated with a {@link ResourceServer} with the given <code>resourceServerId</code>.
     *
     * @param resourceServerId the identifier of a resource server
     * @return a list of policies that belong to the given resource server
     */
    List<Policy> findByResourceServer(String resourceServerId);

    /**
     * Returns a list of {@link Policy} associated with a {@link org.keycloak.authz.core.model.Resource} with the given <code>resourceId</code>.
     *
     * @param resourceId the identifier of a resource
     * @return a list of policies associated with the given resource
     */
    List<Policy> findByResource(String resourceId);

    /**
     * Returns a list of {@link Policy} associated with a {@link org.keycloak.authz.core.model.Resource} with the given <code>type</code>.
     *
     * @param resourceType     the type of a resource
     * @param resourceServerId the resource server id
     * @return a list of policies associated with the given resource type
     */
    List<Policy> findByResourceType(String resourceType, String resourceServerId);

    /**
     * Returns a list of {@link Policy} associated with a {@link org.keycloak.authz.core.model.Scope} with the given <code>scopeNames</code>.
     *
     * @param scopeNames the name of the scopes
     * @param resourceServerId the resource server id
     * @return a list of policies associated with the given scope names
     */
    List<Policy> findByScopeName(List<String> scopeNames, String resourceServerId);

    /**
     * Returns a list of {@link Policy} with the given <code>type</code>.
     *
     * @param type the type of the policy
     * @return a list of policies with the given type
     */
    List<Policy> findByType(String type);

    /**
     * Returns a list of {@link Policy} that depends on another policy with the given <code>id</code>.
     *
     * @param id the id of the policy to query its dependents
     * @return a list of policies that depends on the a policy with the given identifier
     */
    List<Policy> findDependentPolicies(String id);
}
