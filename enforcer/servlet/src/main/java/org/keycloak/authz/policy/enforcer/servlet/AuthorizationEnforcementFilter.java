package org.keycloak.authz.policy.enforcer.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.AuthorizationRequest;
import org.keycloak.authz.client.representation.AuthorizationResponse;
import org.keycloak.authz.client.representation.EntitlementResponse;
import org.keycloak.authz.client.representation.Permission;
import org.keycloak.authz.client.representation.PermissionRequest;
import org.keycloak.authz.client.representation.PermissionResponse;
import org.keycloak.authz.client.representation.RegistrationResponse;
import org.keycloak.authz.client.representation.RequestingPartyToken;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.policy.enforcer.servlet.Configuration.PathConfig;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.ClientErrorException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationEnforcementFilter implements Filter {

    private List<PathConfig> paths = new ArrayList<>();
    private AuthzClient authzClient;
    private Configuration configuration;
    private PathMatcher pathMatcher;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        InputStream is = filterConfig.getServletContext().getClassLoader().getResourceAsStream("keycloak-authz.json");

        if (is == null) {
            throw new RuntimeException("Configuration file[keycloak-authz.json] not found in classpath.");
        }

        this.authzClient = AuthzClient.create();

        try {
            this.configuration = new ObjectMapper().readValue(is, Configuration.class);
            AuthzClient.ProtectionClient protection = this.authzClient.protection();
            Configuration.EnforcerConfig enforcerConfig = this.configuration.getEnforcer();

            if (enforcerConfig.getPaths().isEmpty()) {
                Set<String> resourceIds = protection.resource().findAll();

                for (String id : resourceIds) {
                    RegistrationResponse response = protection.resource().findById(id);
                    ResourceRepresentation resourceDescription = response.getResourceDescription();

                    if (resourceDescription != null) {
                        this.paths.add(createPathConfig(resourceDescription));
                    }
                }
            } else {
                enforcerConfig.getPaths().forEach(pathConfig -> {
                    Set<String> search = protection.resource().search("uri=" + pathConfig.getPath());

                    if (search.isEmpty()) {
                        if (enforcerConfig.isCreateResources()) {
                            ResourceRepresentation resource = new ResourceRepresentation();

                            resource.setName(pathConfig.getName());
                            resource.setType(pathConfig.getType());
                            resource.setUri(pathConfig.getPath());

                            HashSet<ScopeRepresentation> scopes = new HashSet<>();

                            pathConfig.getScopes().forEach(scopeName -> {
                                ScopeRepresentation scope = new ScopeRepresentation();

                                scope.setName(scopeName);

                                scopes.add(scope);
                            });

                            resource.setScopes(scopes);

                            RegistrationResponse registrationResponse = protection.resource().create(resource);

                            pathConfig.setId(registrationResponse.getId());
                        } else {
                            throw new RuntimeException("Could not find resource on server with uri [" + pathConfig.getPath() + "].");
                        }
                    } else {
                        pathConfig.setId(search.iterator().next());
                    }

                    this.paths.add(pathConfig);
                });
            }

            this.pathMatcher = new PathMatcher();
        } catch (IOException e) {
            throw new RuntimeException("Failed to load configuration.", e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestURI = httpRequest.getRequestURI();
        String path = requestURI.substring(httpRequest.getContextPath().length());
        PathConfig pathConfig = this.pathMatcher.matches(path, this.paths);

        if (pathConfig != null) {
            KeycloakSecurityContext keycloakSecurityContext = getKeycloakSecurityContext(request);
            String rpt = getAuthorizationToken(keycloakSecurityContext, httpRequest, pathConfig);

            if (rpt != null) {
                RequestingPartyToken authzToken;

                try {
                    authzToken = extractRequestingPartyToken(rpt);
                } catch (JWSInputException e) {
                    throw new RuntimeException("Could not parse authorization token.", e);
                }

                if (authzToken.isValid()) {
                    for (Permission permission : authzToken.getPermissions()) {
                        if (permission.getResourceSetId().equals(pathConfig.getId())
                                && permission.getScopes().containsAll(pathConfig.getScopes())) {
                            try {
                                propagateAuthorizationContext(httpRequest, rpt, authzToken);
                                chain.doFilter(request, response);
                                return;
                            } catch (Exception e) {
                                throw new RuntimeException("Error processing path [" + requestURI + "].", e);
                            }
                        }
                    }
                }

                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid authorization token.");
                return;
            }
        }

        httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    public KeycloakSecurityContext getKeycloakSecurityContext(ServletRequest request) {
        KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());

        if (keycloakSecurityContext == null) {
            throw new RuntimeException("Could not obtain " + KeycloakSecurityContext.class.getName() + ". Check if your configuration.");
        }
        return keycloakSecurityContext;
    }

    @Override
    public void destroy() {

    }

    private String requestAuthorizationToken(HttpServletRequest httpRequest, KeycloakSecurityContext keycloakSecurityContext, PathConfig pathConfig) {
        PermissionRequest permissionRequest = new PermissionRequest(pathConfig.getId(), pathConfig.getScopes().toArray(new String[pathConfig.getScopes().size()]));
        PermissionResponse permissionResponse = this.authzClient.protection().permission().forResource(permissionRequest);

        try {
            if (this.configuration.getEnforcer().isEntitlements()) {
                EntitlementResponse authzResponse = this.authzClient.entitlement(keycloakSecurityContext.getTokenString()).get(this.authzClient.getClientConfiguration().getClient().getClientId());
                return authzResponse.getRpt();
            } else {
                AuthorizationContext authzContext = getAuthorizationContext(httpRequest);
                AuthorizationRequest authzRequest;

                if (authzContext != null) {
                    authzRequest = new AuthorizationRequest(permissionResponse.getTicket(), authzContext.getAuthzTokenString());
                } else {
                    authzRequest = new AuthorizationRequest(permissionResponse.getTicket());
                }

                AuthorizationResponse authzResponse = this.authzClient.authorization(keycloakSecurityContext.getTokenString()).authorize(authzRequest);
                return authzResponse.getRpt();
            }
        } catch (ClientErrorException e) {
            int status = e.getResponse().getStatus();

            if (HttpServletResponse.SC_FORBIDDEN == status) {
                return null;
            }

            throw new RuntimeException("Unexpected error during authorization request.", e);
        }
    }

    private AuthorizationContext getAuthorizationContext(HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession(false);
        return (AuthorizationContext) session.getAttribute(AuthorizationContext.class.getName());
    }

    private RequestingPartyToken extractRequestingPartyToken(String token) throws JWSInputException {
        return new JWSInput(token).readJsonContent(RequestingPartyToken.class);
    }

    private  PathConfig createPathConfig(ResourceRepresentation resourceDescription) {
        PathConfig pathConfig = new PathConfig();

        pathConfig.setId(resourceDescription.getId());
        pathConfig.setName(resourceDescription.getName());
        pathConfig.setPath(resourceDescription.getUri());
        pathConfig.setScopes(resourceDescription.getScopes().stream().map(ScopeRepresentation::getName).collect(Collectors.toList()));
        pathConfig.setType(resourceDescription.getType());

        return pathConfig;
    }

    private void propagateAuthorizationContext(HttpServletRequest httpRequest, String rpt, RequestingPartyToken authzToken) {
        AuthorizationContext newAuthorizationContext = new AuthorizationContext(authzToken, rpt, this.paths);
        HttpSession session = httpRequest.getSession(false);

        if (session != null) {
            session.setAttribute(AuthorizationContext.class.getName(), newAuthorizationContext);
        }

        httpRequest.setAttribute(Authorization.class.getName(), newAuthorizationContext);
    }

    private String getAuthorizationToken(KeycloakSecurityContext keycloakSecurityContext, HttpServletRequest httpRequest, PathConfig pathConfig) {
        AuthorizationContext authzContext = getAuthorizationContext(httpRequest);

        if (authzContext != null) {
            RequestingPartyToken authzToken = authzContext.getAuthzToken();

            if (authzToken.isValid()) {
                return authzContext.getAuthzTokenString();
            } else {
                return requestAuthorizationToken(httpRequest, keycloakSecurityContext, pathConfig);
            }
        } else {
            return requestAuthorizationToken(httpRequest, keycloakSecurityContext, pathConfig);
        }
    }
}
