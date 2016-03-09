package org.keycloak.authz.persistence.jpa;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.Config;
import org.keycloak.connections.jpa.DefaultJpaConnectionProvider;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.connections.jpa.JpaConnectionProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.kohsuke.MetaInfServices;

import javax.naming.InitialContext;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.sql.DataSource;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(JpaConnectionProviderFactory.class)
public class DefaultJPAConnectionProviderFactory implements JpaConnectionProviderFactory, ServerInfoAwareProviderFactory {

    public static final String CONNECTION_PROVIDER_ID = "keycloak-authz-admin-jpa";
    private EntityManagerFactory entityManagerFactory;
    private Config.Scope config;

    @Override
    public Map<String, String> getOperationalInfo() {
        HashMap<String, String> info = new LinkedHashMap<>();
        Map<String, Object> properties = this.entityManagerFactory.getProperties();
        String dataSourceUrl = (String) properties.get("javax.persistence.nonJtaDataSource");

        try {
            if (dataSourceUrl != null) {
                DataSource dataSource = (DataSource) new InitialContext().lookup(dataSourceUrl);

                try (Connection connection = dataSource.getConnection()) {
                    DatabaseMetaData md = connection.getMetaData();

                    info.put("databaseUrl", md.getURL());
                    info.put("databaseUser", md.getUserName());
                    info.put("databaseProduct", md.getDatabaseProductName() + " " + md.getDatabaseProductVersion());
                    info.put("databaseDriver", md.getDriverName() + " " + md.getDriverVersion());
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to obtain info for provider [" + getId() + "].", e);
        }

        return info;
    }

    @Override
    public Connection getConnection() {
        try {
            String dataSourceLookup = config.get("dataSource");
            if (dataSourceLookup != null) {
                DataSource dataSource = (DataSource) new InitialContext().lookup(dataSourceLookup);
                return dataSource.getConnection();
            } else {
                Class.forName(config.get("driver"));
                return DriverManager.getConnection(config.get("url"), config.get("user"), config.get("password"));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to connect to database", e);
        }
    }

    @Override
    public String getSchema() {
        return config.get("schema");
    }

    @Override
    public JpaConnectionProvider create(KeycloakSession session) {
        return new DefaultJpaConnectionProvider(this.entityManagerFactory.createEntityManager());
    }

    @Override
    public void init(Config.Scope config) {
        this.config = config;
        this.entityManagerFactory = createEntityManagerFactory();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return CONNECTION_PROVIDER_ID;
    }

    private EntityManagerFactory createEntityManagerFactory() {
        Map<Object, Object> map = new HashMap<>();
        List<Object> value = new ArrayList<>();

        value.add(getClass().getClassLoader());

        map.put("hibernate.classLoaders", value);
        map.put("hibernate.classLoader.application", getClass().getClassLoader());

        return Persistence.createEntityManagerFactory(CONNECTION_PROVIDER_ID + "-pu", map);
    }
}
