package org.keycloak.authz.policy.enforcer.servlet;

import org.codehaus.jackson.map.ObjectMapper;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.resource.AuthorizationResource;
import org.keycloak.authz.server.uma.authorization.AuthorizationRequest;
import org.keycloak.authz.server.uma.authorization.AuthorizationResponse;
import org.keycloak.authz.server.uma.authorization.Permission;
import org.keycloak.authz.server.uma.authorization.RequestingPartyToken;
import org.keycloak.authz.server.uma.protection.permission.PermissionRequest;
import org.keycloak.authz.server.uma.protection.permission.PermissionResponse;
import org.keycloak.authz.server.uma.protection.resource.RegistrationResponse;
import org.keycloak.authz.server.uma.representation.UmaResourceRepresentation;
import org.keycloak.authz.server.uma.representation.UmaScopeRepresentation;
import org.keycloak.jose.jws.JWSInput;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.ClientErrorException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationEnforcementFilter implements Filter {

    private List<PathHolder> paths = new ArrayList<>();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        InputStream is = filterConfig.getServletContext().getClassLoader().getResourceAsStream("keycloak-authz.json");

        if (is == null) {
            throw new RuntimeException("Configuration file[keycloak-authz.json] not found in classpath.");
        }

        try {
            Configuration configuration = new ObjectMapper().readValue(is, Configuration.class);
            AuthzClient.ProtectionClient protection = AuthzClient.create().protection();
            Configuration.EnforcerConfig enforcerConfig = configuration.getEnforcer();

            enforcerConfig.getPaths().forEach(new Consumer<Configuration.PathConfig>() {
                @Override
                public void accept(Configuration.PathConfig pathConfig) {
                    Set<String> search = protection.resource().search("uri=" + pathConfig.getPath());

                    if (search.isEmpty()) {
                        if (enforcerConfig.isCreateResources()) {
                            UmaResourceRepresentation resource = new UmaResourceRepresentation();

                            resource.setName(pathConfig.getName());
                            resource.setType(pathConfig.getType());
                            resource.setUri(pathConfig.getPath());

                            HashSet<UmaScopeRepresentation> scopes = new HashSet<>();

                            pathConfig.getScopes().forEach(scopeName -> {
                                UmaScopeRepresentation scope = new UmaScopeRepresentation();

                                scope.setName(scopeName);

                                scopes.add(scope);
                            });

                            resource.setScopes(scopes);

                            RegistrationResponse registrationResponse = protection.resource().create(resource);

                            paths.add(new PathHolder(registrationResponse.getId(), pathConfig));
                        } else {
                            throw new RuntimeException("Could not find resource on server with uri [" + pathConfig.getPath() + "].");
                        }
                    } else {
                        paths.add(new PathHolder(search.iterator().next(), pathConfig));
                    }
                }
            });
        } catch (IOException e) {
            throw new RuntimeException("Failed to load configuration.", e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());

        if (keycloakSecurityContext == null) {
            throw new RuntimeException("Could not obtain " + KeycloakSecurityContext.class.getName() + ". Check if your configuration.");
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestURI = httpRequest.getRequestURI();

        httpRequest.getSession().invalidate();

        for (PathHolder pathHolder : this.paths) {
            Map<String, String> pathParams = new HashMap<>();
            String path = requestURI.substring(httpRequest.getContextPath().length());

            if (pathHolder.getTemplate().matches(path, pathParams)) {
                Configuration.PathConfig pathConfig = pathHolder.getConfig();
                PermissionRequest permissionRequest = new PermissionRequest(pathHolder.getId(), pathConfig.getScopes().toArray(new String[pathConfig.getScopes().size()]));
                PermissionResponse permissionResponse = AuthzClient.create().protection().permission().forResource(permissionRequest);
                AuthorizationResource authorization = AuthzClient.create().authorization(keycloakSecurityContext.getTokenString());
                AuthorizationResponse authorize;

                try {
                    authorize = authorization.authorize(new AuthorizationRequest(permissionResponse.getTicket()));
                } catch (ClientErrorException e) {
                    int status = e.getResponse().getStatus();

                    if (HttpServletResponse.SC_FORBIDDEN == status) {
                        httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        return;
                    }

                    throw new RuntimeException("Authorization failed.", e);
                }

                String rpt = authorize.getRpt();

                if (rpt != null) {
                    RequestingPartyToken authzToken;

                    try {
                        authzToken = extractRequestingPartyToken(rpt);
                    } catch (IOException e) {
                        throw new RuntimeException("Could not parse authorization token.", e);
                    }

                    for (Permission permission : authzToken.getPermissions()) {
                        if (permission.getResourceSetId().equals(pathHolder.getId())
                                && permission.getScopes().containsAll(pathConfig.getScopes())) {
                            try {
                                chain.doFilter(request, response);
                                return;
                            } catch (Exception e) {
                                throw new RuntimeException("Error processing path [" + requestURI + "].", e);
                            }
                        }
                    }
                }
            }
        }

        httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }

    @Override
    public void destroy() {

    }

    public RequestingPartyToken extractRequestingPartyToken(String token) throws IOException {
        return new JWSInput(token).readJsonContent(RequestingPartyToken.class);
    }
}
