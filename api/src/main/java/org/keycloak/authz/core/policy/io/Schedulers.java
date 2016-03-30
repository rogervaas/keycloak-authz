package org.keycloak.authz.core.policy.io;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Schedulers {

    public static Scheduler blocking() {
        return new Scheduler(new Executor() {
            @Override
            public void execute(Runnable command) {
                command.run();
            }
        });
    }

    public static Scheduler single() {
        return new Scheduler(Executors.newSingleThreadExecutor());
    }

    public static class Scheduler {

        private final Executor executor;

        public Scheduler(Executor executor) {
            this.executor = executor;
        }

        Executor getExecutor() {
            return this.executor;
        }
    }
}
