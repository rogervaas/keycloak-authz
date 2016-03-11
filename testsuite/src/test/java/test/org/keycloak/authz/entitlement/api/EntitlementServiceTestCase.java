package test.org.keycloak.authz.entitlement.api;

import org.junit.Test;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.EntitlementResponse;
import org.keycloak.authz.client.resource.EntitlementResource;
import org.keycloak.authz.server.entitlement.resource.EntitlementToken;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EntitlementServiceTestCase {

    @Test
    public void testObtainPermissionTicket() throws Exception {
        AuthzClient client = AuthzClient.create();
        EntitlementResource entitlement = client.entitlement("alice", "alice", "photoz-restful-api", "secret");
        EntitlementResponse all = entitlement.get("photoz-restful-api");
        String rpt = all.getRpt();

        try {
            JWSInput jws = new JWSInput(rpt);
            EntitlementToken entitlementToken = jws.readJsonContent(EntitlementToken.class);

            entitlementToken.toString();
        } catch (Exception e) {
            throw new ErrorResponseException("invalid_ticket", "Unexpected error while validating ticket.", Response.Status.BAD_REQUEST);
        }
    }
}
