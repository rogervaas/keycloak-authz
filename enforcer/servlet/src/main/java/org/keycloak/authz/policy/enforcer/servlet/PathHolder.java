package org.keycloak.authz.policy.enforcer.servlet;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PathHolder {

    private String id;
    private Configuration.PathConfig config;
    private PathTemplate template;

    public PathHolder(String id, Configuration.PathConfig config) {
        this.id = id;
        this.config = config;
        this.template = PathTemplate.create(config.getPath());
    }

    public String getId() {
        return id;
    }

    public Configuration.PathConfig getConfig() {
        return config;
    }

    public PathTemplate getTemplate() {
        return template;
    }
}
