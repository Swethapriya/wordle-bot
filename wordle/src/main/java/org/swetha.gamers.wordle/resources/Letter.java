package org.swetha.gamers.wordle.resources;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class Letter {
    int frequency;
    int[] positions;
}
