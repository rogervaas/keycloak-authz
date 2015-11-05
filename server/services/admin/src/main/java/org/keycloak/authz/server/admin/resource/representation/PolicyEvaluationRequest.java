package org.keycloak.authz.server.admin.resource.representation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEvaluationRequest {

    private Map<String, Map<String, String>> context;
    private List<Resource> resources;
    private String clientId;
    private String userId;
    private List<String> roleIds;

    public Map<String, Map<String, String>> getContext() {
        return this.context;
    }

    public void setContext(Map<String, Map<String, String>> context) {
        this.context = context;
    }

    public List<Resource> getResources() {
        return this.resources;
    }

    public void setResources(List<Resource> resources) {
        this.resources = resources;
    }

    public String getClientId() {
        return this.clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public List<String> getRoleIds() {
        return this.roleIds;
    }

    public void setRoleIds(List<String> roleIds) {
        this.roleIds = roleIds;
    }

    public static class Resource {
        private String id;
        private String name;
        private String type;
        private Set<String> scopes;

        public String getId() {
            return this.id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getName() {
            return this.name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getType() {
            return type;
        }

        public void setType(final String type) {
            this.type = type;
        }

        public Set<String> getScopes() {
            return scopes;
        }

        public void setScopes(final Set<String> scopes) {
            this.scopes = scopes;
        }
    }
}
