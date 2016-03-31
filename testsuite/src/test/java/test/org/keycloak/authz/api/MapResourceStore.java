package test.org.keycloak.authz.api;

import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.ResourceStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapResourceStore implements ResourceStore {

    private Map<String, Resource> resources = new HashMap<>();

    @Override
    public Resource create(String name, ResourceServer resourceServer, String owner) {
        return new MapResource(name, resourceServer, owner);
    }

    @Override
    public void save(Resource resource) {
        MapResource mapResource = (MapResource) resource;

        mapResource.setId(Identifiers.generateId());

        this.resources.put(mapResource.getId(), mapResource);
    }

    @Override
    public void delete(String id) {
        this.resources.remove(id);
    }

    @Override
    public Resource findById(String id) {
        return this.resources.get(id);
    }

    @Override
    public List<Resource> findByOwner(String ownerId) {
        return this.resources.values().stream().filter(resource -> resource.getOwner().equals(ownerId)).collect(Collectors.toList());
    }

    @Override
    public List<Resource> findByResourceServer(String resourceServerId) {
        return this.resources.values().stream().filter(resource -> resource.getResourceServer().getId().equals(resourceServerId)).collect(Collectors.toList());
    }

    @Override
    public List<Resource> findByScope(String... id) {
        return this.resources.values().stream().filter(new Predicate<Resource>() {
            @Override
            public boolean test(Resource resource) {
                return resource.getScopes().stream().filter(new Predicate<Scope>() {
                    @Override
                    public boolean test(Scope scope) {
                        return scope.getId().equals(id);
                    }
                }).findFirst().isPresent();
            }
        }).collect(Collectors.toList());
    }

    @Override
    public Resource findByName(String name) {
        return this.resources.values().stream().filter(resource -> resource.getName().equals(name)).findFirst().orElse(null);
    }

    @Override
    public List<Resource> findByType(String type) {
        return this.resources.values().stream().filter(resource -> resource.getType().equals(type)).collect(Collectors.toList());
    }
}
