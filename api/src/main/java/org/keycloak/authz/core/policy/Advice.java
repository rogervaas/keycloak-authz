package org.keycloak.authz.core.policy;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Advice {

    public static Builder withCategory(String category) {
        return new Builder(category);
    }

    private String category;
    private Map<String, List<String>> properties;

    private Advice(String category, Map<String, List<String>> properties) {
        this.category = category;
        this.properties = properties;
    }

    public String getCategory() {
        return this.category;
    }

    public Map<String, List<String>> getProperties() {
        return this.properties;
    }

    public static class Builder {

        private final String category;
        private Map<String, List<String>> properties = new HashMap();

        public Builder(String category) {
            this.category = category;
        }

        public Builder addProperty(String name, String... value) {
            this.properties.put(name, Arrays.asList(value));
            return this;
        }

        public Advice build() {
            return new Advice(this.category, this.properties);
        }
    }
}
