package org.keycloak.authz.policy.enforcer.servlet;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Configuration {

    private EnforcerConfig enforcer;

    public EnforcerConfig getEnforcer() {
        return enforcer;
    }

    public void setEnforcer(EnforcerConfig enforcer) {
        this.enforcer = enforcer;
    }

    public static class EnforcerConfig {

        private boolean createResources;
        private List<PathConfig> paths;

        public boolean isCreateResources() {
            return this.createResources;
        }

        public void setCreateResources(boolean createResources) {
            this.createResources = createResources;
        }

        public List<PathConfig> getPaths() {
            return this.paths;
        }

        public void setPaths(List<PathConfig> paths) {
            this.paths = paths;
        }
    }

    public static class PathConfig {

        private String name;
        private String type;
        private String path;
        private List<String> scopes;

        public String getPath() {
            return this.path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public List<String> getScopes() {
            return this.scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }
    }
}
