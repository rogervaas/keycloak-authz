/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package test.org.keycloak.authz.uma.api.protection;

import org.junit.Test;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.resource.ProtectedResource;
import org.keycloak.authz.server.uma.protection.resource.RegistrationResponse;
import org.keycloak.authz.server.uma.representation.UmaResourceRepresentation;
import org.keycloak.authz.server.uma.representation.UmaScopeRepresentation;

import javax.ws.rs.NotFoundException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceServiceTestCase {

    /**
     * <p>Considers that the client is an resource server that is also the owner of the resources. In this case, we're covering
     * use cases where an organization is also the owner of its resources and they are not specific to a specific person. In UMA,
     * they call that NPE or Non-Person Entity.
     *
     * <p>In this case we use oAuth2 Client Credentials Grant Type, where the resource server is a confidential client.
     */
    @Test
    public void testCreateResourceServerIsResourceOwner() {
        String resourceName = "Admin Resources";
        String resourceUri = "http://photoz.example.com/admin/*";
        String resourceType = "http://www.keycloak-authz.org/rtype/uri";
        Set<UmaScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/admin"));

        UmaResourceRepresentation resourceDescription = new UmaResourceRepresentation(resourceName, scopes,
                resourceUri,
                resourceType);
        ProtectedResource resource = createAuthzClient()
                .protection()
                .resource();
        RegistrationResponse response = resource.create(resourceDescription);
        String resourceId = response.getId();

        assertNotNull(resourceId);

        UmaResourceRepresentation newResourceDescription = resource.findById(resourceId).getResourceDescription();

        assertNotNull(newResourceDescription.getId());
        assertEquals(resourceName, newResourceDescription.getName());
        assertEquals(resourceUri, newResourceDescription.getUri());
        assertEquals(resourceType, newResourceDescription.getType());

        Set<UmaScopeRepresentation> registeredScopes = newResourceDescription.getScopes();

        assertEquals(1, registeredScopes.size());
        assertTrue(registeredScopes.containsAll(scopes));
    }

    private AuthzClient createAuthzClient() {
        return AuthzClient.fromConfig(URI.create("http://localhost:8080/auth/realms/photoz/authz/uma_configuration"));
    }

    /**
     * <p>Considers that the resource server is acting on behalf of the resource owner. In this case, the resource is owned
     * by a person (eg.: some user). In UMA, this usually means that the owner can later define whatever and whenever configure the policies
     * he wants, given to the owner full control on which policies should be applied for his resources.
     *
     * <p>In this case we may consider a oAuth2 Authorization Code Grant Type. However, in this test we are using "password" grant type to make things
     * easier.
     */
    @Test
    public void testCreateResourceServerOnBehalfOfResourceOwner() {
        String resourceName = "Jdoe Family's Album";
        String resourceUri = "http://photoz.example.com/jdoe/family_album";
        String resourceType = "http://www.keycloak-authz.org/rtype/photoalbum";
        String resourceIcon = "http://photoz.example.com/jdoe/family_album/icon";
        Set<UmaScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/view", "http://photoz.example.com/icons/reading-glasses"));
        scopes.add(new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/all", "http://photoz.example.com/icons/permit-all"));

        UmaResourceRepresentation resourceDescription = new UmaResourceRepresentation(resourceName, scopes,
                resourceUri,
                resourceType,
                resourceIcon);
        ProtectedResource resource = createAuthzClient()
                .protection("jdoe", "jdoe")
                .resource();
        RegistrationResponse response = resource.create(resourceDescription);
        String resourceId = response.getId();

        assertNotNull(resourceId);

        UmaResourceRepresentation newResourceDescription = resource.findById(resourceId).getResourceDescription();

        assertNotNull(newResourceDescription.getId());
        assertEquals(resourceName, newResourceDescription.getName());
        assertEquals(resourceUri, newResourceDescription.getUri());
        assertEquals(resourceType, newResourceDescription.getType());
        assertEquals(resourceIcon, newResourceDescription.getIconUri());

        Set<UmaScopeRepresentation> registeredScopes = newResourceDescription.getScopes();

        assertEquals(2, registeredScopes.size());
        assertTrue(registeredScopes.containsAll(scopes));
    }

    @Test
    public void testListOwnerResources() {
        ProtectedResource resource = createAuthzClient()
                .protection("jdoe", "jdoe")
                .resource();

        resource.deleteAll();

        for (int i = 0; i < 10; i++) {
            resource.create(newResource("Jdoe Party Album " + i, new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/all")));
        }

        Set<String> resourceNames = new HashSet<>();

        for (String id : resource.findAll()) {
            UmaResourceRepresentation description = resource.findById(id).getResourceDescription();

            assertTrue(description.getName().startsWith("Jdoe Party Album"));
            assertTrue(resourceNames.add(description.getName()));
        }

        assertEquals(10, resourceNames.size());
    }

    @Test(expected = NotFoundException.class)
    public void testDeleteOwnerResources() {
        ProtectedResource resource = createAuthzClient()
                .protection("jdoe", "jdoe")
                .resource();

        resource.deleteAll();

        resource.create(newResource("Jdoe Party Album", new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/all")));

        Set<String> rsids = resource.findAll();

        assertEquals(1, rsids.size());

        String resourceId = rsids.iterator().next();
        UmaResourceRepresentation description = resource.findById(resourceId).getResourceDescription();

        assertTrue(description.getName().equals("Jdoe Party Album"));

        resource.delete(resourceId);

        assertNull(resource.findById(resourceId).getId());
    }

    @Test (expected = NotFoundException.class)
    public void testDeleteResourceNotFound() {
        ProtectedResource resource = createAuthzClient()
                .protection("jdoe", "jdoe")
                .resource();

        resource.delete("invalid_resource_id");
    }

    @Test
    public void testDeleteAllOwnerResources() {
        ProtectedResource resource = createAuthzClient()
                .protection("jdoe", "jdoe")
                .resource();

        resource.deleteAll();

        Set<String> rsids = new HashSet<>();

        for (int i = 0; i < 10; i++) {
            rsids.add(resource.create(newResource("Jdoe Party Album " + i, new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/all"))).getId());
        }

        resource.deleteAll();

        for (String rsid : rsids) {
            try {
                assertNull(resource.findById(rsid).getResourceDescription());
            } catch (NotFoundException ignore) {
            } catch (Exception e) {
                e.printStackTrace();
                fail("Unexpected exception.");
            }
        }
    }

    @Test
    public void testSearchOwnerIsPersion() {
        ProtectedResource resource = createAuthzClient()
                .protection("jdoe", "jdoe")
                .resource();

        resource.deleteAll();

        for (int i = 0; i < 10; i++) {
            resource.create(newResource("Jdoe Party Album " + i, new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/all")));
        }

        Set<String> resourceNames = new HashSet<>();

        for (String id : resource.search("all")) {
            UmaResourceRepresentation description = resource.findById(id).getResourceDescription();

            assertTrue(description.getName().startsWith("Jdoe Party Album"));
            assertTrue(resourceNames.add(description.getName()));
        }

        assertEquals(10, resourceNames.size());
    }

    @Test
    public void testSearchResourceServer() {
        ProtectedResource resource = createAuthzClient()
                .protection("jdoe", "jdoe")
                .resource();

        resource.deleteAll();

        Set<String> ownerResources = new HashSet<>();

        for (int i = 0; i < 10; i++) {
            ownerResources.add(resource.create(newResource("Jdoe Party Album " + i, new UmaScopeRepresentation("http://photoz.example.com/dev/scopes/all"))).getId());
        }

        resource = createAuthzClient()
                .protection("photoz-restful-api", "06cb5239-8ade-4c06-a65b-2aadb4e8ee51")
                .resource();

        Set<String> allServerResources = resource.search("all");

        ownerResources.stream().forEach(expectedRsId -> assertTrue(allServerResources.contains(expectedRsId)));
    }

    private UmaResourceRepresentation newResource(String name, UmaScopeRepresentation... scopes) {
        return new UmaResourceRepresentation(name, new HashSet<>(Arrays.asList(scopes)));
    }
}