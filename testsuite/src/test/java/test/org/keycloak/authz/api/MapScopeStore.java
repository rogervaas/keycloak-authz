package test.org.keycloak.authz.api;

import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.ScopeStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapScopeStore implements ScopeStore {

    private Map<String, Scope> scopes = new HashMap<>();

    @Override
    public Scope create(String name, ResourceServer resourceServer) {
        return new MapScope(name, resourceServer);
    }

    @Override
    public void save(Scope scope) {
        MapScope mapScope = (MapScope) scope;

        mapScope.setId(Identifiers.generateId());

        this.scopes.put(mapScope.getId(), mapScope);
    }

    @Override
    public void delete(String id) {
        this.scopes.remove(id);
    }

    @Override
    public Scope findById(String id) {
        return this.scopes.get(id);
    }

    @Override
    public Scope findByName(String name) {
        return this.scopes.values().stream().filter(scope -> scope.getName().equals(name)).findFirst().orElse(null);
    }

    @Override
    public List<Scope> findByResourceServer(String id) {
        return this.scopes.values().stream().filter(scope -> scope.getResourceServer().getId().equals(id)).collect(Collectors.toList());
    }
}
