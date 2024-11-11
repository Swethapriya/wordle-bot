package org.swetha.gamers.wordle.endpoints;

import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.springframework.stereotype.Component;
import org.swetha.gamers.wordle.resources.Wordle;
import org.swetha.gamers.wordle.service.Guesser;

@Path("/wordle")
@Component
public class solver {
    @GET
    @Path("/guess")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public String getCombination(@Valid Wordle wordle) {
        return Guesser.guess(wordle);
    }
}
