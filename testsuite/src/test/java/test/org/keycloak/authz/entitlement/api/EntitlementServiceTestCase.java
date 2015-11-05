package test.org.keycloak.authz.entitlement.api;

import java.net.URI;
import java.util.Map;
import org.junit.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.resource.EntitlementResource;
import org.keycloak.authz.server.entitlement.resource.EntitlementToken;
import org.keycloak.jose.jws.JWSInput;

import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EntitlementServiceTestCase {

    @Test
    public void testObtainPermissionTicket() throws Exception {
        AuthzClient client = AuthzClient.fromConfig(URI.create("http://localhost:8080/auth/realms/photoz/authz/uma_configuration"));
        EntitlementResource entitlement = client.entitlement("alice", "alice", "photoz-restful-api", "06cb5239-8ade-4c06-a65b-2aadb4e8ee51");
        Response all = entitlement.findAll();
        Map map = all.readEntity(Map.class);
        EntitlementToken token = new JWSInput(map.get("entitlement_token").toString()).readJsonContent(EntitlementToken.class);

        token.toString();
    }

    private Keycloak createKeycloakAdminClient() {
        return Keycloak.getInstance("http://localhost:8080/auth", "photoz",
                "alice", "alice",
                "photoz-restful-api", "06cb5239-8ade-4c06-a65b-2aadb4e8ee51");
    }
}
