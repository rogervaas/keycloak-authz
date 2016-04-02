package org.keycloak.authz.core.attribute;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import static java.util.Collections.emptyList;

/**
 * Holds attributes with string values.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Attributes {

    Attributes EMPTY = Collections::emptyMap;

    static Attributes from(Map<String, Collection<String>> attributes) {
        return () -> attributes;
    }

    Map<String, Collection<String>> toMap();

    default boolean exists(String name) {
        return toMap().containsKey(name);
    }

    default boolean containsValue(String name, String value) {
        return toMap().getOrDefault(name, emptyList()).stream().anyMatch(value::equals);
    }
}
