package org.keycloak.authz.persistence.syncronization;

import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RealmSynchronizer implements Synchronizer<RealmModel.RealmRemovedEvent> {
    @Override
    public void synchronize(RealmModel.RealmRemovedEvent event, StoreFactory persistenceProvider) {
        event.getRealm().getClients().forEach(clientModel -> {
            ResourceServer resourceServer = persistenceProvider.getResourceServerStore().findByClient(clientModel.getClientId());

            if (resourceServer != null) {
                String id = resourceServer.getId();
                persistenceProvider.getResourceStore().findByResourceServer(id).forEach(resource -> persistenceProvider.getResourceStore().delete(resource.getId()));
                persistenceProvider.getScopeStore().findByResourceServer(id).forEach(scope -> persistenceProvider.getScopeStore().delete(scope.getId()));
                persistenceProvider.getPolicyStore().findByResourceServer(id).forEach(scope -> persistenceProvider.getPolicyStore().remove(scope.getId()));
                persistenceProvider.getResourceServerStore().delete(id);
            }
        });
    }
}
