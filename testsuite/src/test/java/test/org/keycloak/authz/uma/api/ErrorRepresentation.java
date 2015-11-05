package test.org.keycloak.authz.uma.api;

import org.codehaus.jackson.annotate.JsonProperty;

import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ErrorRepresentation {

    private String error;
    @JsonProperty("error_description")
    private String errorDescription;
    private Response.Status status;

    public String getError() {
        return error;
    }

    public void setError(final String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(final String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public Response.Status getStatus() {
        return status;
    }

    public void setStatus(final Response.Status status) {
        this.status = status;
    }
}
