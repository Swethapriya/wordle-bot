package org.endpoints;

import org.resources.Wordle;
import org.service.Guesser;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/wordle")
@RestController
public class solver {
    @GetMapping("/guess")
    public String getCombination( Wordle wordle) {
        return Guesser.guess(wordle);
    }
}
