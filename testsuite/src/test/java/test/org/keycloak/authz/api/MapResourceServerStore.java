package test.org.keycloak.authz.api;

import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.models.ClientModel;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapResourceServerStore implements ResourceServerStore {

    private Map<String, ResourceServer> resourceServers = new HashMap<>();

    @Override
    public ResourceServer create(ClientModel clientModel) {
        return new MapResourceServer(clientModel.getId());
    }

    @Override
    public void save(ResourceServer resourceServer) {
        MapResourceServer mapResourceServer = (MapResourceServer) resourceServer;

        mapResourceServer.setId(Identifiers.generateId());

        this.resourceServers.put(mapResourceServer.getId(), mapResourceServer);
    }

    @Override
    public void delete(String id) {
        this.resourceServers.remove(id);
    }

    @Override
    public ResourceServer findById(String id) {
        return this.resourceServers.get(id);
    }

    @Override
    public List<ResourceServer> findByRealm(String realmId) {
        return Collections.emptyList();
    }

    @Override
    public ResourceServer findByClient(String id) {
        return this.resourceServers.values().stream().filter(resourceServer -> resourceServer.getClientId().equals(id)).findFirst().orElse(null);
    }
}
