package test.org.keycloak.authz.api;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.persistence.jpa.entity.ResourceEntity;
import org.keycloak.authz.persistence.jpa.entity.ScopeEntity;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapResourceServer implements ResourceServer {

    @Getter
    @Setter
    private String id;

    @Getter
    @Setter
    private String clientId;

    @Getter
    @Setter
    private String realmId;

    @Getter
    @Setter
    private boolean allowRemoteResourceManagement;

    @Getter
    @Setter
    private boolean allowRemotePolicyManagement;

    @Getter
    @Setter
    private PolicyEnforcementMode policyEnforcementMode;

    @Getter
    @Setter
    private List<ResourceEntity> resources;

    @Getter
    @Setter
    private List<ScopeEntity> scopes;

    public MapResourceServer(String clientId) {
        this.clientId = clientId;
    }
}
