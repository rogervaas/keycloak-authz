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

import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.RegistrationResponse;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.authz.client.resource.ProtectedResource;

import javax.ws.rs.NotFoundException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceServiceTestCase extends AbstractProtectionTestCase {

    private Keycloak keycloak;
    private AuthzClient authzClient;

    @Before
    public void onBefore() {
        this.authzClient = AuthzClient.create();
        this.keycloak = Keycloak.getInstance(authzClient.getServerConfiguration().getServerUrl().toString(), "master", "admin", "admin", "admin-cli");
    }

    /**
     * <p>Considers that the client is an resource server that is also the owner of the resources. In this case, we're covering
     * use cases where an organization is also the owner of its resources and they are not specific to a specific person. In UMA,
     * they call that NPE or Non-Person Entity.
     *
     * <p>In this case we use oAuth2 Client Credentials Grant Type, where the resource server is a confidential client.
     */
    @Test
    public void testCreateResourceServerIsResourceOwner() {
        String resourceName = "Resource Server's Resource";
        String resourceUri = "http://photoz.example.com/resources/*";
        String resourceType = "http://www.keycloak-authz.org/rtype/internal";
        String resourceIcon = "http://www.keycloak-authz.org/icon";
        Set<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new ScopeRepresentation("http://photoz.example.com/dev/scopes/internal"));

        ResourceRepresentation newResourceDescription = createResource(resourceName, resourceUri, resourceType, resourceIcon, null, scopes);

        assertNotNull(newResourceDescription.getId());
        assertEquals(resourceName, newResourceDescription.getName());
        assertEquals(resourceUri, newResourceDescription.getUri());
        assertEquals(resourceType, newResourceDescription.getType());

        Set<ScopeRepresentation> registeredScopes = newResourceDescription.getScopes();

        assertEquals(1, registeredScopes.size());
        assertTrue(registeredScopes.containsAll(scopes));
    }

    private AuthzClient createAuthzClient() {
        return AuthzClient.create();
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
        String resourceOwner = getOwnerId("jdoe");
        Set<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new ScopeRepresentation("http://photoz.example.com/dev/scopes/view", "http://photoz.example.com/icons/reading-glasses"));
        scopes.add(new ScopeRepresentation("http://photoz.example.com/dev/scopes/all", "http://photoz.example.com/icons/permit-all"));

        ResourceRepresentation newResourceDescription = createResource(resourceName, resourceUri, resourceType, resourceIcon, resourceOwner, scopes);

        assertNotNull(newResourceDescription.getId());
        assertEquals(resourceName, newResourceDescription.getName());
        assertEquals(resourceUri, newResourceDescription.getUri());
        assertEquals(resourceType, newResourceDescription.getType());
        assertEquals(resourceIcon, newResourceDescription.getIconUri());

        Set<ScopeRepresentation> registeredScopes = newResourceDescription.getScopes();

        assertEquals(2, registeredScopes.size());
        assertTrue(registeredScopes.containsAll(scopes));
    }

    public String getOwnerId(String userName) {
        return this.keycloak.realm("photoz").users().search(userName, null, null, null, null, null).get(0).getId();
    }

    @Test
    public void testListOwnerResources() {
        ProtectedResource resource = authzClient.protection().resource();
        String ownerId = getOwnerId("jdoe");
        Set<String> search = resource.search("owner=" + ownerId);

        if (search != null) {
            search.forEach(resource::delete);
        }

        for (int i = 0; i < 10; i++) {
            createResource("Jdoe Party Album " + i, null, null, null, ownerId, null);
        }

        Set<String> resourceNames = new HashSet<>();

        for (String id : resource.search("owner=" + ownerId)) {
            ResourceRepresentation description = resource.findById(id).getResourceDescription();

            assertTrue(description.getName().startsWith("Jdoe Party Album"));
            assertTrue(resourceNames.add(description.getName()));
        }

        assertEquals(10, resourceNames.size());
    }

    @Test(expected = NotFoundException.class)
    public void testDeleteOwnerResources() {
        ResourceRepresentation resource = createResource("Jdoe Party Album to Delete", null, null, null, getOwnerId("jdoe"), null);
        String resourceId = resource.getId();
        ProtectedResource resourceService = this.authzClient.protection().resource();
        ResourceRepresentation description = resourceService.findById(resourceId).getResourceDescription();

        assertTrue(description.getName().equals("Jdoe Party Album to Delete"));

        resourceService.delete(resourceId);

        assertNull(resourceService.findById(resourceId).getId());
    }

    @Test
    public void testDeleteAllResources() {
        ProtectedResource resource = this.authzClient.protection().resource();
        Set<String> search = resource.findAll();

        if (search != null) {
            search.forEach(resource::delete);
        }

        Set<String> rsids = new HashSet<>();

        for (int i = 0; i < 10; i++) {
            rsids.add(createResource("Jdoe Party Album " + i, null, null, null, null, null).getId());
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
}