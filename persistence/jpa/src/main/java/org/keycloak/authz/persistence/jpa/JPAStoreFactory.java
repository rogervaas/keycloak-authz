package org.keycloak.authz.persistence.jpa;

import org.keycloak.authz.core.store.PolicyStore;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.authz.core.store.ResourceStore;
import org.keycloak.authz.core.store.ScopeStore;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.authz.persistence.jpa.store.JPAPolicyStore;
import org.keycloak.authz.persistence.jpa.store.JPAResourceServerStore;
import org.keycloak.authz.persistence.jpa.store.JPAResourceStore;
import org.keycloak.authz.persistence.jpa.store.JPAScopeStore;
import org.kohsuke.MetaInfServices;

import javax.persistence.EntityManager;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(StoreFactory.class)
public class JPAStoreFactory implements StoreFactory {

    private final EntityManager entityManager;

    public JPAStoreFactory(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public PolicyStore getPolicyStore() {
        return new JPAPolicyStore(this.entityManager);
    }

    @Override
    public ResourceServerStore getResourceServerStore() {
        return new JPAResourceServerStore(this.entityManager);
    }

    @Override
    public ResourceStore getResourceStore() {
        return new JPAResourceStore(this.entityManager);
    }

    @Override
    public ScopeStore getScopeStore() {
        return new JPAScopeStore(this.entityManager);
    }
}
