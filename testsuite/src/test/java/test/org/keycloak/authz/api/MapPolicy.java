package test.org.keycloak.authz.api;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapPolicy implements Policy {

    @Getter
    @Setter
    private String id;

    @Getter
    @Setter
    private String name;

    @Getter
    @Setter
    private String description;

    @Getter
    @Setter
    private String type;

    @Getter
    @Setter
    private DecisionStrategy decisionStrategy;

    @Getter
    @Setter
    private Map<String, String> config = new HashMap();

    @Getter
    @Setter
    private ResourceServer resourceServer;

    @Getter
    @Setter
    private Set<Policy> associatedPolicies = new HashSet<>();

    @Getter
    @Setter
    private Set<Resource> resources = new HashSet<>();

    @Getter
    @Setter
    private Set<Scope> scopes = new HashSet<>();
    private Logic logic;

    public MapPolicy(String name, String type, ResourceServer resourceServer) {
        this.name = name;
        this.type = type;
        this.resourceServer = resourceServer;
    }

    @Override
    public void addAssociatedPolicy(Policy policy) {
        this.associatedPolicies.add(policy);
    }

    @Override
    public void removeAssociatedPolicy(Policy policy) {
        this.associatedPolicies.remove(policy);
    }

    @Override
    public Logic getLogic() {
        return this.logic;
    }

    @Override
    public void setLogic(Logic logic) {
        this.logic = logic;
    }

    @Override
    public void addScope(Scope scope) {
        this.scopes.add(scope);
    }

    @Override
    public void removeScope(Scope scope) {
        this.scopes.remove(scope);
    }

    @Override
    public void addResource(Resource resource) {
        this.resources.add(resource);
    }

    @Override
    public void removeResource(Resource resource) {
        this.resources.remove(resource);
    }
}
