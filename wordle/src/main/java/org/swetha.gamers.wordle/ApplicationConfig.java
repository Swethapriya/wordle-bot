package org.swetha.gamers.wordle;

import org.springframework.stereotype.Component;
import org.swetha.gamers.wordle.endpoints.solver;

@Component
public class ApplicationConfig extends ResourceConfig {
    public ApplicationConfig() {
        register(solver.class);
    }
}