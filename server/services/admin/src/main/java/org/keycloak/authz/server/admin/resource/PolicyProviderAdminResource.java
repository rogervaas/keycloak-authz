package org.keycloak.authz.server.admin.resource;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyProviderAdminResource {

    String getType();

    void init(ResourceServer resourceServer);

    void create(Policy policy);

    void update(Policy policy);

    void remove(Policy policy);
}
