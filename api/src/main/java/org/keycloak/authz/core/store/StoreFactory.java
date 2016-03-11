package org.keycloak.authz.core.store;

import org.keycloak.authz.core.store.PolicyStore;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.authz.core.store.ResourceStore;
import org.keycloak.authz.core.store.ScopeStore;

/**
 * <p>A factory for the different types of storages that manage the persistence of the domain model types.
 *
 * <p>Implementations of this interface are usually related with the creation of those storage types accordingly with a
 * specific persistence mechanism such as relational and NoSQL databases, filesystem, etc.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface StoreFactory {

    /**
     * Returns a {@link ResourceStore}.
     *
     * @return the resource store
     */
    ResourceStore getResourceStore();

    /**
     * Returns a {@link ResourceServerStore}.
     *
     * @return the resource server store
     */
    ResourceServerStore getResourceServerStore();

    /**
     * Returns a {@link ScopeStore}.
     *
     * @return the scope store
     */
    ScopeStore getScopeStore();

    /**
     * Returns a {@link PolicyStore}.
     *
     * @return the policy store
     */
    PolicyStore getPolicyStore();

}
