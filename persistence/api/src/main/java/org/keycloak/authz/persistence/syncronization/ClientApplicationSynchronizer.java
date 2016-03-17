package org.keycloak.authz.persistence.syncronization;

import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.models.RealmModel;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ClientApplicationSynchronizer implements Synchronizer<RealmModel.ClientRemovedEvent> {

    @Override
    public void synchronize(RealmModel.ClientRemovedEvent clientEvent, StoreFactory storeFactory) {
        ResourceServerStore store = storeFactory.getResourceServerStore();
        ResourceServer resourceServer = store.findByClient(clientEvent.getClient().getId());

        if (resourceServer != null) {
            String id = resourceServer.getId();
            storeFactory.getResourceStore().findByResourceServer(id).forEach(resource -> storeFactory.getResourceStore().delete(resource.getId()));
            storeFactory.getScopeStore().findByResourceServer(id).forEach(scope -> storeFactory.getScopeStore().delete(scope.getId()));
            storeFactory.getPolicyStore().findByResourceServer(id).forEach(scope -> storeFactory.getPolicyStore().remove(scope.getId()));
            storeFactory.getResourceServerStore().delete(id);
        }
    }
}
