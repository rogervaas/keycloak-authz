package org.keycloak.authz.client;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientConfiguration {

    private Config client;

    public Config getClient() {
        return this.client;
    }

    public void setClient(Config client) {
        this.client = client;
    }

    public static class Config {

        private String configurationUrl;
        private String clientId;
        private String clientSecret;

        public String getConfigurationUrl() {
            return this.configurationUrl;
        }

        public void setConfigurationUrl(String configurationUrl) {
            this.configurationUrl = configurationUrl;
        }

        public String getClientId() {
            return this.clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return this.clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }
    }

}
