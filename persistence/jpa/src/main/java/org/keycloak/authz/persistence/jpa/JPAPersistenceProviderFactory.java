package org.keycloak.authz.persistence.jpa;

import org.keycloak.authz.core.store.spi.PersistenceProvider;
import org.keycloak.authz.persistence.PersistenceProviderFactory;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.connections.jpa.JpaKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.kohsuke.MetaInfServices;

import javax.persistence.EntityManager;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PersistenceProviderFactory.class)
public class JPAPersistenceProviderFactory implements PersistenceProviderFactory {

    @Override
    public PersistenceProvider create(KeycloakSession keycloakSession) {
        EntityManager entityManager = getEntityManager(keycloakSession);

        keycloakSession.getTransaction().enlist(new JpaKeycloakTransaction(entityManager));

        return new JPAPersistenceProvider(entityManager);
    }

    public EntityManager getEntityManager(KeycloakSession keycloakSession) {
        JpaConnectionProvider jpaProvider = keycloakSession.getProvider(JpaConnectionProvider.class, DefaultJPAConnectionProviderFactory.CONNECTION_PROVIDER_ID);

        if (jpaProvider == null) {
            throw new RuntimeException("Could not obtain a " + JpaConnectionProvider.class + ". Expected a provider with id [" + DefaultJPAConnectionProviderFactory.CONNECTION_PROVIDER_ID + "].");
        }

        return jpaProvider.getEntityManager();
    }
}
