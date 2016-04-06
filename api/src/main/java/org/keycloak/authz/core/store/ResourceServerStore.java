package org.keycloak.authz.core.store;

import org.keycloak.authz.core.model.ResourceServer;

/**
 * A {@link ResourceServerStore} is responsible to manage the persistence of {@link ResourceServer} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface ResourceServerStore {

    /**
     * <p>Creates a {@link ResourceServer} instance backed by this persistent storage implementation.
     *
     * @param clientModel the client application to be turned as a resource server
     *
     * @return an instance backed by the underlying storage implementation
     */
    ResourceServer create(String clientId);

    /**
     * Saves a new or an existing {@link ResourceServer} instance.
     *
     * @param resourceServer the instance to save
     */
    void save(ResourceServer resourceServer);

    /**
     * Removes a {@link ResourceServer} instance, with the given {@code id} from the persistent storage.
     *
     * @param id the identifier of an existing resource server instance
     */
    void delete(String id);

    /**
     * Returns a {@link ResourceServer} instance based on its identifier.
     *
     * @param id the identifier of an existing resource server instance
     *
     * @return the resource server instance with the given identifier or null if no instance was found
     */
    ResourceServer findById(String id);

    /**
     * Returns a {@link ResourceServer} instance based on the identifier of a client application.
     *
     * @param id the identifier of an existing client application
     * 
     * @return the resource server instance, with the given client id or null if no instance was found
     */
    ResourceServer findByClient(String id);
}
