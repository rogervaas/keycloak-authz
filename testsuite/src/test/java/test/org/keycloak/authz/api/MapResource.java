package test.org.keycloak.authz.api;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapResource implements Resource {

    @Getter
    @Setter
    private String id;

    @Getter
    @Setter
    private String name;

    @Getter
    @Setter
    private String uri;

    @Getter
    @Setter
    private String type;

    @Getter
    @Setter
    private List<Scope> scopes = new ArrayList<>();

    @Getter
    @Setter
    private String iconUri;

    @Getter
    @Setter
    private String owner;

    @Getter
    @Setter
    private ResourceServer resourceServer;

    @Getter
    @Setter
    private List<Policy> policies = new ArrayList<>();

    public MapResource(String name, ResourceServer resourceServer, String owner) {
        this.name = name;
        this.resourceServer = resourceServer;
        this.owner = owner;
    }

    @Override
    public void addScope(Scope scope) {
        this.scopes.add((Scope) scope);
    }

    @Override
    public void removeScope(Scope scope) {
        this.scopes.remove(scope);
    }

    @Override
    public void updateScopes(Set<Scope> toUpdate) {
        for (Scope scope : toUpdate) {
            boolean hasScope = false;

            for (Scope existingScope : this.scopes) {
                if (existingScope.equals(scope)) {
                    hasScope = true;
                }
            }

            if (!hasScope) {
                addScope(scope);
            }
        }

        for (Scope scopeModel : new HashSet<Scope>(this.scopes)) {
            boolean hasScope = false;

            for (Scope scope : toUpdate) {
                if (scopeModel.equals(scope)) {
                    hasScope = true;
                }
            }

            if (!hasScope) {
                removeScope(scopeModel);
            }
        }
    }
}
