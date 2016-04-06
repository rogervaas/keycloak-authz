package test.org.keycloak.authz.api;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapPolicyStore implements PolicyStore {

    private Map<String, Policy> policies = new HashMap<>();

    @Override
    public Policy create(String name, String type, ResourceServer resourceServer) {
        return new MapPolicy(name, type, resourceServer);
    }

    @Override
    public void save(Policy policy) {
        MapPolicy mapPolicy = (MapPolicy) policy;

        mapPolicy.setId(Identifiers.generateId());

        this.policies.put(mapPolicy.getId(), policy);
    }

    @Override
    public void remove(String id) {
        this.policies.remove(id);
    }

    @Override
    public Policy findById(String id) {
        return this.policies.get(id);
    }

    @Override
    public Policy findByName(String name, String resourceServerId) {
        return this.policies.values().stream().filter(policy -> policy.getResourceServer().getId().equals(resourceServerId) && policy.getName().equals(name)).findFirst().get();
    }

    @Override
    public List<Policy> findByResourceServer(String resourceServerId) {
        return this.policies.values().stream().filter(policy -> policy.getResourceServer().getId().equals(resourceServerId)).collect(Collectors.toList());
    }

    @Override
    public List<Policy> findByResource(String resourceId) {
        return this.policies.values().stream().filter(policy -> policy.getResources().stream().filter(resource -> resource.getId().equals(resourceId)).findFirst().isPresent()).collect(Collectors.toList());
    }

    @Override
    public List<Policy> findByResourceType(String resourceType, String resourceServerId) {
        return this.policies.values().stream().filter(policy -> policy.getResourceServer().getId().equals(resourceServerId) && policy.getConfig().getOrDefault("defaultResourceType", "").equals(resourceType)).collect(Collectors.toList());
    }

    @Override
    public List<Policy> findByScopeName(List<String> scopeNames, String resourceServerId) {
        return this.policies.values().stream()
                .filter(policy -> policy.getResourceServer().getId().equals(resourceServerId) && policy.getScopes().stream().filter(scope -> scopeNames.stream()
                        .filter(s -> scope.getName().equals(s))
                        .findFirst()
                        .isPresent())
                    .findFirst()
                    .isPresent())
                    .collect(Collectors.toList());
    }

    @Override
    public List<Policy> findByType(String type) {
        return this.policies.values().stream().filter(policy -> policy.getType().equals(type)).collect(Collectors.toList());
    }

    @Override
    public List<Policy> findDependentPolicies(String id) {
        return this.policies.values().stream().filter(policy -> policy.getAssociatedPolicies().stream()
                .filter(policy1 -> policy1.getId().equals(id))
                .findFirst()
                .isPresent())
                .collect(Collectors.toList());
    }
}
