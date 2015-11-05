package org.keycloak.authz.core.model.util;

import java.util.UUID;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Identifiers {

    public static String generateId() {
        return UUID.randomUUID().toString();
    }
}
