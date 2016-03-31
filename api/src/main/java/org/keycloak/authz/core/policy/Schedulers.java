package org.keycloak.authz.core.policy;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Schedulers {

    public static Scheduler sync() {
        return new Scheduler(new Executor() {
            @Override
            public void execute(Runnable command) {
                command.run();
            }
        });
    }

    public static Scheduler parallel() {
        return new Scheduler(Executors.newWorkStealingPool());
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
