package org.keycloak.authz.server.admin.resource.representation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyProviderRepresentation {

    private String type;
    private String name;
    private String group;

    public String getType() {
        return this.type;
    }

    public void setType( String type) {
        this.type = type;
    }

    public String getName() {
        return this.name;
    }

    public void setName( String name) {
        this.name = name;
    }

    public String getGroup() {
        return this.group;
    }

    public void setGroup( String group) {
        this.group = group;
    }
}
