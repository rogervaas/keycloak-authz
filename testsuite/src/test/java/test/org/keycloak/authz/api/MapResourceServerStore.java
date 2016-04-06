package test.org.keycloak.authz.api;

import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.ResourceServerStore;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapResourceServerStore implements ResourceServerStore {

    private Map<String, ResourceServer> resourceServers = new HashMap<>();

    @Override
    public ResourceServer create(String clientId) {
        return new MapResourceServer(clientId);
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
    public ResourceServer findByClient(String id) {
        return this.resourceServers.values().stream().filter(resourceServer -> resourceServer.getClientId().equals(id)).findFirst().orElse(null);
    }
}
