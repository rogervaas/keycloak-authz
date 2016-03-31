package test.org.keycloak.authz.api;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapScope implements Scope {

    @Getter
    @Setter
    private String id;

    @Getter
    @Setter
    private String name;

    @Getter
    @Setter
    private String iconUri;

    @Getter
    @Setter
    private ResourceServer resourceServer;

    @Getter
    @Setter
    private List<Policy> policies = new ArrayList<>();

    public MapScope(String name, ResourceServer resourceServer) {
        this.name = name;
        this.resourceServer = resourceServer;
    }
}
