package org.keycloak.authz.policy.provider.drools.api;

import org.keycloak.authz.core.attribute.Attributes;
import org.keycloak.authz.core.identity.Identity;

/**
 * Wraps an existing {@link Identity} in order to provide additional methods that make life easier when writing rules.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CallerIdentity implements Identity {

    private final Identity delegate;

    public CallerIdentity(Identity delegate) {
        this.delegate = delegate;
    }

    @Override
    public String getId() {
        return this.delegate.getId();
    }

    @Override
    public Attributes getAttributes() {
        return this.delegate.getAttributes();
    }

    /**
     * Indicates if this identity is granted with a role with the given <code>roleName</code>.
     *
     * @param roleName the name of the role
     *
     * @return true if the identity has the given role. Otherwise, it returns false.
     */
    public boolean hasRole(String roleName) {
        return getAttributes().containsValue("roles", roleName);
    }
}
