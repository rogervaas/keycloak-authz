package org.keycloak.authz.client;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ErrorResponseFilter implements ClientResponseFilter {
    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        Response.StatusType statusInfo = responseContext.getStatusInfo();

        if (!statusInfo.getFamily().equals(Response.Status.Family.SUCCESSFUL)) {
            StringBuffer buffer = new StringBuffer();

            if (responseContext.hasEntity()) {
                new BufferedReader(new InputStreamReader(responseContext.getEntityStream())).lines().forEach(buffer::append);
            }

            throw new RuntimeException("Server returned an error [" + statusInfo.getReasonPhrase() + "] with status [" + statusInfo.getStatusCode() + "]: " + buffer.toString());
        }
    }
}
