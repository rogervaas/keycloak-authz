package org.keycloak.authz.policy.enforcer.jaxrs;


import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ProtectedResource {
    String name();
    String type() default "";
    String uri() default "";
    ProtectedScope[] scopes() default {};
}
