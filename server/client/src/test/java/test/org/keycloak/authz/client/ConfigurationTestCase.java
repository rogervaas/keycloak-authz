package test.org.keycloak.authz.client;

import org.junit.Test;
import org.keycloak.authz.client.AuthzClient;

import static org.junit.Assert.assertNotNull;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ConfigurationTestCase {

    @Test
    public void testConfigFromKeycloakAuthzJson() {
        AuthzClient instance = AuthzClient.create();
        assertNotNull(instance);
    }

}
