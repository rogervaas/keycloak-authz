package test.org.keycloak.authz.uma.api.protection;

import org.junit.After;
import org.junit.Before;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.ClientConfiguration;
import org.keycloak.authz.client.representation.Configuration;
import org.keycloak.authz.client.representation.RegistrationResponse;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.authz.client.resource.ProtectedResource;
import org.keycloak.representations.idm.ClientRepresentation;

import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import static org.junit.Assert.assertNotNull;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractProtectionTestCase {

    protected ClientRepresentation clientApplication;
    protected AuthzClient authzClient;
    private Keycloak keycloakAdminClient;

    @Before
    public void onSetup() {
        this.keycloakAdminClient = createKeycloakAdminClient();
        this.clientApplication = createClientApplication();
        this.authzClient = AuthzClient.create(ClientConfiguration.builder()
                .configurationUrl("http://localhost:8080/auth/realms/photoz/authz/uma_configuration")
                .clientId(this.clientApplication.getClientId())
                .clientSecret(this.clientApplication.getSecret())
                .build());
    }

    @After
    public void onAfter() {
//        this.keycloakAdminClient.realm("photoz").clients().get(this.clientApplication.getId()).remove();
    }

    protected ResourceRepresentation createResource(String resourceName, String resourceUri, String resourceType, String resourceIcon, String resourceOwner, Set<ScopeRepresentation> scopes) {
        AuthzClient.ProtectionClient protectionClient = this.authzClient.protection();
        ProtectedResource resourceClient = protectionClient.resource();
        Set<String> search = resourceClient.search("name=" + resourceName);

        if (search != null) {
            search.forEach(resourceId -> resourceClient.delete(resourceId));
        }

        if (scopes == null) {
            scopes = Collections.emptySet();
        }

        ResourceRepresentation resourceDescription = new ResourceRepresentation(resourceName, scopes,
                resourceUri,
                resourceType,
                resourceIcon);

        resourceDescription.setOwner(resourceOwner);

        RegistrationResponse response = resourceClient.create(resourceDescription);
        String resourceId = response.getId();

        assertNotNull(resourceId);

        return resourceClient.findById(resourceId).getResourceDescription();
    }

    protected ClientRepresentation getClientApplication(String clientId) {
        for (ClientRepresentation client : this.keycloakAdminClient.realm("photoz").clients().findAll()) {
            if (client.getClientId() != null && client.getClientId().equals(clientId)) {
                return client;
            }
        }
        return null;
    }

    private Keycloak createKeycloakAdminClient() {
        AuthzClient client = AuthzClient.create();
        Configuration configuration = client.getServerConfiguration();
        return Keycloak.getInstance(configuration.getServerUrl().toString(), configuration.getRealm(),
                "admin", "admin",
                "admin-cli");
    }

    private ClientRepresentation createClientApplication() {
        ClientRepresentation representation = new ClientRepresentation();

        representation.setClientId("resource-server-test");
        representation.setSecret("secret");
        representation.setName("Resource Server Test");
        representation.setServiceAccountsEnabled(true);
        representation.setPublicClient(false);
        representation.setBearerOnly(false);
        representation.setRedirectUris(Arrays.asList("http://localhost:8080/resourceServerTest"));

//        RealmResource realm = this.keycloakAdminClient.realm("photoz");
//        Response response = realm.clients().create(representation);
//        response.close();

        ClientRepresentation client = getClientApplication("photoz-restful-api");

        if (client != null) {
            client.setSecret(representation.getSecret());
            return client;
        }

        throw new RuntimeException("No client application was created.");
    }
}
