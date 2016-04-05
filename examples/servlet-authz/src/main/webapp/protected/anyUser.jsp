<%@ page import="org.keycloak.constants.ServiceUrlConstants" %>
<%@ page import="org.keycloak.common.util.KeycloakUriBuilder" %>
<%@page import="org.keycloak.authz.policy.enforcer.servlet.AuthorizationContext" %>
<%@ page import="org.keycloak.authz.client.representation.Permission" %>

<%
    AuthorizationContext authzContext = (AuthorizationContext) session.getAttribute(AuthorizationContext.class.getName());
%>

<html>
<body>

<h2>Any authenticated user can access this page. Click <a href="<%= KeycloakUriBuilder.fromUri("/auth").path(ServiceUrlConstants.TOKEN_SERVICE_LOGOUT_PATH)
            .queryParam("redirect_uri", "/servlet-authz-app").build("servlet-authz").toString()%>">here</a> to logout.</h2>

<p>Here is a dynamic menu built from the permissions returned by the server:</p>

<ul>
    <%
        if (authzContext.hasPermission("Protected Resource")) {
    %>
    <li>
        Do any user thing
    </li>
    <%
        }
    %>

    <%
        if (authzContext.hasPermission("Admin Resource", "http://servlet-authz/protected/admin/access")) {
    %>
    <li>
        Do administration thing
    </li>
    <%
        }
    %>
</ul>

<h3>Your permissions are:</h3>

<ul>
    <%
        for (Permission permission : authzContext.getPermissions()) {
    %>
    <li>
        <p>Resource: <%= permission.getResourceSetId() %></p>
        <p>Scopes: <%= permission.getScopes() %></p>
    </li>
    <%
        }
    %>
</ul>

</body>
</html>