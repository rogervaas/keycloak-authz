package org.keycloak.authz.core.store;

import org.keycloak.authz.core.store.spi.PersistenceProvider;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultStoreFactory implements StoreFactory {

    private final PersistenceProvider persistenceProvider;

    public DefaultStoreFactory(PersistenceProvider persistenceProvider) {
        this.persistenceProvider = persistenceProvider;
    }

    @Override
    public ResourceStore resource() {
        return this.persistenceProvider.getResourceStore();
    }

    @Override
    public ResourceServerStore resourceServer() {
        return this.persistenceProvider.getResourceServerStore();
    }

    @Override
    public ScopeStore scope() {
        return this.persistenceProvider.getScopeStore();
    }

    @Override
    public PolicyStore policy() {
        return this.persistenceProvider.getPolicyStore();
    }
}
