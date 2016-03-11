package org.keycloak.authz.persistence;

import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.authz.persistence.syncronization.ClientApplicationSynchronizer;
import org.keycloak.authz.persistence.syncronization.RealmSynchronizer;
import org.keycloak.authz.persistence.syncronization.Synchronizer;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderEvent;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PersistenceProviderFactory {

    StoreFactory create(KeycloakSession keycloakSession);

    default void registerSynchronizationListeners(KeycloakSessionFactory factory) {
        Map<Class<? extends ProviderEvent>, Synchronizer> synchronizers = new HashMap<>();

        synchronizers.put(RealmModel.ClientRemovedEvent.class, new ClientApplicationSynchronizer());
        synchronizers.put(RealmModel.RealmRemovedEvent.class, new RealmSynchronizer());

        factory.register(event -> {
            KeycloakSession session = factory.create();
            KeycloakTransactionManager transaction = session.getTransaction();

            try {
                transaction.begin();

                synchronizers.forEach((eventType, synchronizer) -> {
                    if (eventType.isInstance(event)) {
                        synchronizer.synchronize(event, create(session));
                    }
                });

                transaction.commit();
            } catch (Exception e) {
                transaction.rollback();
            } finally {
                session.close();
            }
        });
    }
}
