package org.swetha.gamers.wordle.service;


import org.swetha.gamers.wordle.resources.Wordle;

import static org.swetha.gamers.wordle.resources.Constants.WORDLE_WORDS;

public class Guesser {
    public static String guess(Wordle wordle) {
        return WORDLE_WORDS.get((int) (Math.random() * WORDLE_WORDS.toArray().length));
    }
}