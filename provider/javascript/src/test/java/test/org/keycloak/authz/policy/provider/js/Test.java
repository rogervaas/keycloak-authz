package test.org.keycloak.authz.policy.provider.js;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Test {

    @org.junit.Test
    public void testEngine() throws Exception {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("nashorn");

        Object eval = engine.eval("a = 1 + 1; b = a + 2; b + a;print(b);");
    }
}
