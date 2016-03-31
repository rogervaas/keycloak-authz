package test.org.keycloak.authz.api;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.persistence.jpa.entity.PolicyEntity;
import org.keycloak.authz.persistence.jpa.entity.ResourceEntity;
import org.keycloak.authz.persistence.jpa.entity.ResourceServerEntity;
import org.keycloak.authz.persistence.jpa.entity.ScopeEntity;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.MapKeyColumn;
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

    public MapPolicy(String name, String type, ResourceServer resourceServer) {
        this.name = name;
        this.type = type;
        this.resourceServer = resourceServer;
    }

    @Override
    public void addAssociatedPolicy(Policy policy) {
        this.associatedPolicies.add((PolicyEntity) policy);
    }

    @Override
    public void removeAssociatedPolicy(Policy policy) {
        this.associatedPolicies.remove(policy);
    }

    @Override
    public void addScope(Scope scope) {
        this.scopes.add((ScopeEntity) scope);
    }

    @Override
    public void removeScope(Scope scope) {
        this.scopes.remove(scope);
    }

    @Override
    public void addResource(Resource resource) {
        this.resources.add((ResourceEntity) resource);
    }

    @Override
    public void removeResource(Resource resource) {
        this.resources.remove(resource);
    }
}