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

import java.util.List;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;

/**
 * Defines a contract for a persistent storage implementation that holds data for {@link Resource} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface ResourceStore {

    /**
     * <p>Creates a {@link Resource} instance backed by this persistent storage implementation.
     *
     * @param name the name of this resource. It must be unique.
     * @param resourceServer the resource server to where the given resource belongs to
     * @param owner the owner of this resource or null if the resource server is the owner
     * @return an instance backed by the underlying storage implementation
     */
    Resource create(String name, ResourceServer resourceServer, String owner);

    /**
     * Saves a new or an existing {@link Resource} instance.
     resource
     * @param resourceServer the instance to save
     */
    void save(Resource resource);

    /**
     * Removes a {@link Resource} instance, with the given {@code id} from the persistent storage.
     *
     * @param id the identifier of an existing resource instance
     */
    void delete(String id);

    /**
     * Returns a {@link Resource} instance based on its identifier.
     *
     * @param id the identifier of an existing resource instance
     * @return the resource instance with the given identifier or null if no instance was found
     */
    Resource findById(String id);

    /**
     * Finds all {@link Resource} instances with the given {@code ownerId}.
     *
     * @param ownerId the identifier of the owner
     * @return a list with all resource instances owned by the given owner
     */
    List<Resource> findByOwner(String ownerId);

    /**
     * Finds all {@link Resource} instances associated with a given resource server.
     *
     * @param resourceServerId the identifier of the resource server
     * @return a list with all resources associated with the given resource server
     */
    List<Resource> findByServer(String resourceServerId);

    /**
     * Finds all {@link Resource} associated with a given scope.
     *
     * @param id one or more scope identifiers
     * @return a list of resources associated with the given scope(s)
     */
    List<Resource> findByScope(String... id);

    /**
     * Find a {@link Resource} by its name.
     *
     * @param name the name of the resource
     * @return a resource with the given name
     */
    Resource findByName(String name);

    /**
     * Finds all {@link Resource} with the given type.
     *
     * @param type the type of the resource
     * @return a list of resources with the given type
     */
    List<Resource> findByType(String type);
}
