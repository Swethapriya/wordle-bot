package org.swetha.gamers.wordle;

import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.stereotype.Component;
import org.swetha.gamers.wordle.endpoints.solver;

@Component
public class ApplicationConfig extends ResourceConfig {
    // TODO(rass-scavenger): File path "/tmp/clone15861756571544415501/wordle/src/main/java/org/swetha.gamers.wordle" should match package name "org.swetha.gamers.wordle". Move the file or change the package name(Do not use dots in directory names).
    public ApplicationConfig() {
        register(solver.class);
    }
}