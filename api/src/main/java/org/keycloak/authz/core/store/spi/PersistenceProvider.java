package org.keycloak.authz.core.store.spi;

import org.keycloak.authz.core.store.PolicyStore;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.authz.core.store.ResourceStore;
import org.keycloak.authz.core.store.ScopeStore;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PersistenceProvider {

    PolicyStore getPolicyStore();
    ResourceServerStore getResourceServerStore();
    ResourceStore getResourceStore();
    ScopeStore getScopeStore();

}
