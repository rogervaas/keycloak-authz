package org.keycloak.authz.core.model;

import java.util.List;

/**
 * Represents a scope, which is usually associated with one or more resources in order to define the actions that can be performed
 * or a specific access context.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Scope {

    /**
     * Returns the unique identifier for this instance.
     *
     * @return the unique identifier for this instance
     */
    String getId();

    /**
     * Returns the name of this scope.
     *
     * @return the name of this scope
     */
    String getName();

    /**
     * Sets a name for this scope. The name must be unique.
     *
     * @param name the name of this scope
     */
    void setName(String name);

    /**
     * Returns an icon {@link java.net.URI} for this scope.
     *
     * @return a uri for an icon
     */
    String getIconUri();

    /**
     * Sets an icon {@link java.net.URI} for this scope.
     *
     * @return a uri for an icon
     */
    void setIconUri(String iconUri);

    /**
     * Returns the {@link ResourceServer} instance to where this scope belongs to.
     *
     * @return
     */
    ResourceServer getResourceServer();

    /**
     * Returns all {@link Policy} instances associated with this resource.
     *
     * @return the policies associated with this resource
     */
    List<? extends Policy> getPolicies();
}
