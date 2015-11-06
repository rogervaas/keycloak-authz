package org.keycloak.authz.policy.enforcer.jaxrs;

import org.codehaus.jackson.map.ObjectMapper;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.ErrorResponse;
import org.keycloak.authz.client.representation.Permission;
import org.keycloak.authz.client.representation.PermissionRequest;
import org.keycloak.authz.client.representation.PermissionResponse;
import org.keycloak.authz.client.representation.RegistrationResponse;
import org.keycloak.authz.client.representation.RequestingPartyToken;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.jose.jws.JWSInput;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationEnforcementFilter implements ContainerRequestFilter {

    private final Map<Class, String> resourceIds;

    @Context
    private ResourceInfo resourceInfo;

    public AuthorizationEnforcementFilter( Map<Class, String> resourceIds) {
        this.resourceIds = resourceIds;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String resourceId = this.resourceIds.get(this.resourceInfo.getResourceClass());
        String authorization = requestContext.getHeaderString("Authorization");
        RequestingPartyToken rpt = extractRequestingPartyToken(authorization);

        if (authorization != null && authorization.indexOf("Bearer") != -1) {
            requestContext.setSecurityContext(createSecurityContext(rpt));
        }

        if (resourceId != null) {
            Class<?> resourceClass = resourceInfo.getResourceClass();
            ProtectedResource protectedResource = resourceClass.getAnnotation(ProtectedResource.class);
            Method resourceMethod = this.resourceInfo.getResourceMethod();
            Enforce enforce = resourceMethod.getAnnotation(Enforce.class);
            Set<String> requiredScopes = new HashSet<>();

            try {

                if (enforce != null) {
                    requiredScopes.addAll(Arrays.asList(enforce.scopes()));
                    String uriPattern = enforce.uri();
                    String uri = uriPattern;

                    if (uriPattern != null && !"".equals(uriPattern)) {
                        MultivaluedMap<String, String> pathParameters = requestContext.getUriInfo().getPathParameters();

                        for (String pathParam: pathParameters.keySet()) {
                            uri = uriPattern.replaceAll("\\{" + pathParam + "\\}", pathParameters.getFirst(pathParam));
                        }
                    }

                    if (!uriPattern.equals(uri)) {
                        Set<String> resourceIds = createAuthzClient().resource().search("uri=" + uri);

                        if (!resourceIds.isEmpty()) {
                            resourceId = resourceIds.iterator().next();
                        } else {
                            throw new RuntimeException("Resource with URI [" + uri + "] does not exist in the server.");
                        }
                    }

                    List<Permission> permissions = rpt.getPermissions();

                    if (!rpt.isActive() || rpt.getType() == null || !"rpt".equals(rpt.getType()) || permissions == null || !hasPermission(resourceId, requiredScopes, permissions)) {
                        requestContext.abortWith(obtainPermissionTicket(resourceId, requiredScopes.toArray(new String[requiredScopes.size()])));
                    } else {
                        requestContext.setSecurityContext(createSecurityContext(rpt));
                    }
                }
            } catch (WebApplicationException cre) {
                String serverResponse = cre.getResponse().readEntity(String.class);

                try {
                    ErrorResponse errorResponse = new ObjectMapper().readValue(serverResponse, ErrorResponse.class);

                    if (errorResponse.getError().equals("nonexistent_resource_set_id")) {
                        HashSet<ScopeRepresentation> scopes = new HashSet<>();

                        for (ProtectedScope protectedScope : protectedResource.scopes()) {
                            scopes.add(new ScopeRepresentation(protectedScope.name(), protectedScope.uri()));
                        }

                        RegistrationResponse response = createAuthzClient().resource().create(
                                new ResourceRepresentation(enforce.uri(), scopes, enforce.uri(), protectedResource.type())
                        );

                        this.resourceIds.put(resourceInfo.getResourceClass(), response.getId());

                        requestContext.abortWith(obtainPermissionTicket(resourceId, requiredScopes.toArray(new String[requiredScopes.size()])));
                    }
                } catch (Exception ignore) {
                    ignore.toString();
                    // ignore
                }

                throw new RuntimeException("Could not request server for permission. Server returned: [" + serverResponse, cre);
            } catch (Exception e) {
                throw new RuntimeException("Unexpected error when asking for permission.", e);
            }
        }
    }

    public RequestingPartyToken extractRequestingPartyToken(String authorization) throws IOException {
        String expectedRpt = authorization.substring("Bearer".length() + 1);
        return new JWSInput(expectedRpt).readJsonContent(RequestingPartyToken.class);
    }

    private  SecurityContext createSecurityContext(final RequestingPartyToken rpt) {
        return new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return rpt::getRequestingPartyId;
            }

            @Override
            public boolean isUserInRole(String role) {
                return false;
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
        PermissionResponse response = createAuthzClient().permission().forResource(new PermissionRequest(resourceId, scopes));
        return Response.status(Response.Status.FORBIDDEN).header(HttpHeaders.WWW_AUTHENTICATE, "UMA realm=\"photoz\", as_uri=\"http://localhost:8080/auth/realms/photoz/authz/\"")
                .entity(response)
                .build();
    }

    private AuthzClient.ProtectionClient createAuthzClient() {
        return AuthzClient.create().protection();
    }

    private boolean hasPermission(String resourceId, Set<String> requiredScopes, List<Permission> permissions) {
        if (permissions != null) {
            for (Permission permission : permissions) {
                if (permission.getResourceSetId().equals(resourceId)) {
                    Set<String> allowedScopes = permission.getScopes();

                    if ((allowedScopes.isEmpty() && requiredScopes.isEmpty()) || allowedScopes.containsAll(requiredScopes)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
