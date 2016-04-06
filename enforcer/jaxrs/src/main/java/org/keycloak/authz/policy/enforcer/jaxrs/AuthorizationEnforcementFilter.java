package org.keycloak.authz.policy.enforcer.jaxrs;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.ErrorResponse;
import org.keycloak.authz.client.representation.Permission;
import org.keycloak.authz.client.representation.PermissionRequest;
import org.keycloak.authz.client.representation.PermissionResponse;
import org.keycloak.authz.client.representation.RequestingPartyToken;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.policy.enforcer.jaxrs.annotation.Enforce;
import org.keycloak.authz.policy.enforcer.jaxrs.annotation.ProtectedResource;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.representations.AccessToken;
import org.omg.PortableInterceptor.SYSTEM_EXCEPTION;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationEnforcementFilter implements ContainerRequestFilter {

    private final Map<Class<?>, Set<ResourceRepresentation>> protectedResources;
    private final AuthzClient authzClient;

    @Context
    private ResourceInfo resourceInfo;

    public AuthorizationEnforcementFilter(Map<Class<?>, Set<ResourceRepresentation>> protectedResources) {
        this.protectedResources = protectedResources;
        this.authzClient = AuthzClient.create();
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (isProtectedResource(this.resourceInfo)) {
            try {
                enforceAuthorization(requestContext, this.resourceInfo);
            } catch (Exception e) {
                throw new RuntimeException("Failed to enforce authorization in resource type[" + this.resourceInfo.getResourceClass() + "].", e);
            }
        }
    }

    private  boolean isProtectedResource(ResourceInfo resourceInfo) {
        return resourceInfo.getResourceClass().isAnnotationPresent(ProtectedResource.class);
    }

    private void enforceAuthorization(ContainerRequestContext requestContext, ResourceInfo resourceInfo) {
        System.out.println(resourceInfo.getResourceMethod());
        Class<?> resourceClass = resourceInfo.getResourceClass();
        Method resourceMethod = resourceInfo.getResourceMethod();
        Enforce enforce = resourceMethod.getAnnotation(Enforce.class);
        Set<String> requiredScopes = new HashSet<>();

        if (enforce != null) {
            requiredScopes.addAll(Arrays.asList(enforce.scopes()));
        }

        ResourceRepresentation protectedResource = getResourceWithUri(resourceClass, enforce, requestContext.getUriInfo());
        RequestingPartyToken rpt = extractRequestingPartyToken(requestContext);

        if (isAuthorized(protectedResource, requiredScopes, rpt)) {
            requestContext.setSecurityContext(createSecurityContext(rpt));
        } else {
            requestContext.abortWith(obtainPermissionTicket(protectedResource.getId(), requiredScopes.toArray(new String[requiredScopes.size()])));
        }
    }

    private ResourceRepresentation getResourceWithUri(Class<?> resourceClass, Enforce enforce, UriInfo uriInfo) {
        String uri = buildUri(uriInfo, enforce);

        if (uri != null) {
            for (ResourceRepresentation resource : this.protectedResources.get(resourceClass)) {
                if (resource.getUri() != null && resource.getUri().equals(uri)) {
                    return resource;
                }
            }

            Set<String> search = this.authzClient.protection().resource().search("uri=" + uri);

            if (!search.isEmpty()) {
                // resource does exist on the server, cache it
                ResourceRepresentation targetResource = this.authzClient.protection().resource().findById(search.iterator().next()).getResourceDescription();

                this.protectedResources.get(resourceClass).add(targetResource);

                return targetResource;
            }
        }

        ResourceRepresentation targetResource = this.protectedResources.get(resourceClass).iterator().next();

        if (targetResource == null) {
            throw new RuntimeException("Could not find any security metadata for resource [" + resourceClass + "].");
        }

        return targetResource;
    }

    private String buildUri(UriInfo uriInfo, Enforce enforce) {
        String uri = null;

        if (enforce != null) {
            String uriPattern = enforce.uri();

            if (uriPattern != null && !"".equals(uriPattern)) {
                MultivaluedMap<String, String> pathParameters = uriInfo.getPathParameters();

                for (String pathParam: pathParameters.keySet()) {
                    uri = uriPattern.replaceAll("\\{" + pathParam + "\\}", pathParameters.getFirst(pathParam));
                }
            }
        }

        return uri;
    }

    private boolean isAuthorized(ResourceRepresentation protectedResource, Set<String> requiredScopes, RequestingPartyToken rpt) {
        if (rpt != null && rpt.isValid()) {
            for (Permission permission : rpt.getPermissions()) {
                Set<String> allowedScopes = permission.getScopes();
                String resourceId = protectedResource.getId();

                if (permission.getResourceSetId() != null) {
                    if (permission.getResourceSetId().equals(resourceId)) {
                        if ((allowedScopes.isEmpty() && requiredScopes.isEmpty()) || allowedScopes.containsAll(requiredScopes)) {
                            return true;
                        }
                    }
                } else {
                    if ((allowedScopes.isEmpty() && requiredScopes.isEmpty()) || allowedScopes.containsAll(requiredScopes)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private RequestingPartyToken extractRequestingPartyToken(ContainerRequestContext requestContext) {
        try {
            String authorizationHeader = requestContext.getHeaderString("Authorization");

            if (authorizationHeader == null) {
                return null;
            }

            String expectedRpt = authorizationHeader.substring("Bearer".length() + 1);
            JWSInput jwsInput = new JWSInput(expectedRpt);

            try {
                if (!RSAProvider.verify(jwsInput, PemUtils.decodePublicKey(authzClient.getServerConfiguration().getRealmPublicKey()))) {
                    return null;
                }
            } catch (Exception e) {
                throw new VerificationException("Token signature not validated.", e);
            }

            RequestingPartyToken rpt = jwsInput.readJsonContent(RequestingPartyToken.class);

            if (!rpt.isValid()) {
                return null;
            }

            return rpt;
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract bearer token from request.", e);
        }
    }

    private  SecurityContext createSecurityContext(final RequestingPartyToken rpt) {
        String accessTokenString = rpt.getAccessToken();
        AccessToken accessToken;

        try {
            accessToken = new JWSInput(accessTokenString).readJsonContent(AccessToken.class);
        } catch (JWSInputException e) {
            throw new RuntimeException("Error building principal.", e);
        }

        return new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return new KeycloakPrincipal<>(rpt.getSubject(), new KeycloakSecurityContext(accessTokenString, accessToken, null, null));
            }

            @Override
            public boolean isUserInRole(String role) {
                return accessToken.getRealmAccess().isUserInRole(role);
            }

            @Override
            public boolean isSecure() {
                return true;
            }

            @Override
            public String getAuthenticationScheme() {
                return "KEYCLOAK_AUTHZ";
            }
        };
    }

    private Response obtainPermissionTicket(String resourceId, String... scopes) {
        try {
            PermissionResponse response = this.authzClient.protection().permission().forResource(new PermissionRequest(resourceId, scopes));
            return Response.status(Response.Status.FORBIDDEN).header(HttpHeaders.WWW_AUTHENTICATE, "as_uri=\"" + this.authzClient.getServerConfiguration().getRptEndpoint() + "\"")
                    .entity(response)
                    .build();
        } catch (WebApplicationException cre) {
            String serverResponse = cre.getResponse().readEntity(String.class);

            try {
                ErrorResponse errorResponse = new ObjectMapper().readValue(serverResponse, ErrorResponse.class);

                if (errorResponse.getError().equals("nonexistent_resource_set_id")) {
                    return Response.status(Response.Status.BAD_REQUEST).entity("Resource not registered in the server.").build();
                }
            } catch (Exception ignore) {
                // ignore
            }

            throw new RuntimeException("Could not obtain permission ticket from the server. Server returned: [" + serverResponse + "].", cre);
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error when asking permission ticket.", e);
        }
    }
}
