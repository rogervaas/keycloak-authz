package org.keycloak.authz.core.model;

import java.util.List;

/**
 * Represents a scope, which is usually associated with one or more resources in order to define the actions that can be performed
 * or even a specific access context.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Scope {

    String getId();

    String getName();

    void setName(String name);

    String getIconUri();

    void setIconUri(String iconUri);

    ResourceServer getResourceServer();

    /**
     * Returns all {@link Policy} associated with this resource.
     *
     * @return the policies associated with this resource
     */
    List<? extends Policy> getPolicies();
}
