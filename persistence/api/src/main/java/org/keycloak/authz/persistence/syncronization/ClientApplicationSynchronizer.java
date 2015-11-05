package org.keycloak.authz.persistence.syncronization;

import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.store.spi.PersistenceProvider;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.models.RealmModel;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ClientApplicationSynchronizer implements Synchronizer<RealmModel.ClientRemovedEvent> {

    @Override
    public void synchronize(RealmModel.ClientRemovedEvent clientEvent, PersistenceProvider persistenceProvider) {
        ResourceServerStore store = persistenceProvider.getResourceServerStore();
        ResourceServer resourceServer = store.findByClient(clientEvent.getClient().getId());

        if (resourceServer != null) {
            store.delete(resourceServer.getId());
        }
    }
}
