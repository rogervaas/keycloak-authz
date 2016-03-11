package org.keycloak.authz.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientConfiguration {

    public static Builder builder() {
        return new Builder();
    }

    private Config client;

    public ClientConfiguration() {
        this(null);
    }

    public ClientConfiguration(Config config) {
        this.client = config;
    }

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

    public static class Builder {

        private Config config = new Config();

        public Builder configurationUrl(String configurationUrl) {
            config.setConfigurationUrl(configurationUrl);
            return this;
        }

        public Builder clientId(String clientId) {
            config.setClientId(clientId);
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            config.setClientSecret(clientSecret);
            return this;
        }

        public ClientConfiguration build() {
            return new ClientConfiguration(this.config);
        }
    }

}
