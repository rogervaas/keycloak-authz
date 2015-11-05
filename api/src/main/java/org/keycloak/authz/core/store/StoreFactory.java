package org.keycloak.authz.core.store;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface StoreFactory {

    ResourceStore resource();
    ResourceServerStore resourceServer();
    ScopeStore scope();
    PolicyStore policy();

}
