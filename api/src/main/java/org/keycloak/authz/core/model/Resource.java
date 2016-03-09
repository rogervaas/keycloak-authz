package org.keycloak.authz.core.model;

import java.util.List;
import java.util.Set;

/**
 * Represents a resource, which is usually protected by a set of policies within a resource server.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Resource {

    /**
     * Returns the unique identifier for this instance.
     *
     * @return the unique identifier for this instance
     */
    String getId();

    /**
     * Returns the resource's name.
     *
     * @return the name of this resource
     */
    String getName();

    /**
     * Sets a name for this resource. The name must be unique.
     *
     * @param name the name of this resource
     */
    void setName(String name);

    /**
     * Returns a {@link java.net.URI} that uniquely identify this resource.
     *
     * @return an {@link java.net.URI} for this resource or null if not defined.
     */
    String getUri();

    /**
     * Sets a {@link java.net.URI} that uniquely identify this resource.
     *
     * @param uri an {@link java.net.URI} for this resource
     */
    void setUri(String uri);

    /**
     * Returns a string representing the type of this resource.
     *
     * @return the type of this resource or null if not defined
     */
    String getType();

    /**
     * Sets a string representing the type of this resource.
     *
     * @return the type of this resource or null if not defined
     */
    void setType(String type);

    /**
     * Returns a {@link List} containing all the {@link Scope} associated with this resource.
     *
     * @return a list with all scopes associated with this resource
     */
    List<Scope> getScopes();

    /**
     * Adds a scope to this resource.
     *
     * @param scope the scope to add
     */
    void addScope(Scope scope);

    /**
     * Removes a scope from this resource.
     *
     * @param scope the scope to remove
     */
    void removeScope(Scope scope);

    /**
     * Updates the scopes associated with this resource.
     *
     * @param toUpdate the scopes to update
     */
    void updateScopes(Set<Scope> toUpdate);

    /**
     * Returns an icon {@link java.net.URI} for this resource.
     *
     * @return a uri for an icon
     */
    String getIconUri();

    /**
     * Sets an icon {@link java.net.URI} for this resource.
     *
     * @return a uri for an icon
     */
    void setIconUri(String iconUri);

    /**
     * Returns the {@link ResourceServer} to where this resource belongs to.
     *
     * @return the resource server associated with this resource
     */
    ResourceServer getResourceServer();

    /**
     * Returns the resource's owner, which is usually an identifier that uniquely identifies the resource's owner.
     *
     * @return the owner of this resource
     */
    String getOwner();

    /**
     * Returns all {@link Policy} instances associated with this resource.
     *
     * @return the policies associated with this resource
     */
    List<? extends Policy> getPolicies();
}
