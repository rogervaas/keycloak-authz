package org.keycloak.authz.policy.provider.time;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.server.admin.resource.PolicyProviderAdminResource;
import org.kohsuke.MetaInfServices;

import java.text.SimpleDateFormat;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderAdminResource.class)
public class TimePolicyAdminResource implements PolicyProviderAdminResource {

    @Override
    public String getType() {
        return "time";
    }

    @Override
    public void init(ResourceServer resourceServer) {
    }

    @Override
    public void create(Policy policy) {
        validateConfig(policy);
    }

    public void validateConfig(Policy policy) {
        String nbf = policy.getConfig().get("nbf");
        String noa = policy.getConfig().get("noa");

        if (nbf == null && noa == null) {
            throw new RuntimeException("You must provide NotBefore, NotOnOrAfter or both.");
        }

        validateFormat(nbf);
        validateFormat(noa);
    }

    public void validateFormat(String date) {
        try {
            new SimpleDateFormat(TimePolicyProvider.DEFAULT_DATE_PATTERN).parse(TimePolicyProvider.format(date));
        } catch (Exception e) {
            throw new RuntimeException("Could not parse a date using format [" + date + "]");
        }
    }

    @Override
    public void update(Policy policy) {
        validateConfig(policy);
    }

    @Override
    public void remove(Policy policy) {
    }
}
