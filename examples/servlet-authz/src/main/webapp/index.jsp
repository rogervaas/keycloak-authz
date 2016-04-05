<%@page import="org.keycloak.authz.policy.enforcer.servlet.AuthorizationContext" %>
<%@ page import="org.keycloak.authz.client.representation.Permission" %>

<%
    AuthorizationContext authzContext = (AuthorizationContext) session.getAttribute(AuthorizationContext.class.getName());
%>

<html>
<body>
    <h2>This is a public resource. Try to access one of these <i>protected</i> resources:</h2>

    <p><a href="protected/anyUser.jsp">Any User</a></p>
    <p><a href="protected/premium/onlyPremium.jsp">User Premium</a></p>
    <p><a href="protected/admin/onlyAdmin.jsp">Administration</a></p>

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
