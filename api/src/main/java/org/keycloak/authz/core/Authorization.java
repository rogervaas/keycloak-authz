package org.keycloak.authz.core;

import org.keycloak.authz.core.policy.PolicyManager;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.StoreFactory;

/**
 * An entry point to all authorization related services.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Authorization {

    /**
     * Returns a {@link PolicyManager}.
     *
     * @return the policy manager
     */
    PolicyManager getPolicyManager();

    /**
     * Returns a {@link StoreFactory}.
     *
     * @return the store factory
     */
    StoreFactory getStoreFactory();

    /**
     * Returns a given policy provider given its <code>type</code>.
     *
     * @param type the type of the policy provider
     * @param <F> the expected type of the provider
     * @return the policy provider with the given type.
     */
    default <F extends PolicyProviderFactory> F getProviderFactory(String type) {
        return (F) getPolicyManager().getProviderFactories().stream().filter(policyProviderFactory -> policyProviderFactory.getType().equals(type)).findFirst().orElse(null);
    }
}
