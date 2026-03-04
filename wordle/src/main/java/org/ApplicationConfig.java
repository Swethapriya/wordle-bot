package org;

import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.stereotype.Component;
import org.endpoints.solver;

@Component
public class ApplicationConfig extends ResourceConfig {
    public ApplicationConfig() {
        register(solver.class);
    }
}

