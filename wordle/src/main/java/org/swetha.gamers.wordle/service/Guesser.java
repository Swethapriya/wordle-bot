package org.swetha.gamers.wordle.service;


import org.swetha.gamers.wordle.resources.Wordle;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

import static org.swetha.gamers.wordle.resources.Constants.ALHPHABET;
import static org.swetha.gamers.wordle.resources.Constants.WORDLE_WORDS;

public class Guesser {
    public HashMap<Character, Integer> frequency;
    public static HashMap<Integer, String> guessValue;
    static ArrayList<Integer> guessSortedValues;

    public Guesser() {
        frequency = new HashMap<>();
        guessValue = new HashMap<>();
        for (int i = 0; i < WORDLE_WORDS.toArray().length; i++) {
            for (int j = 0; j < 26; j ++) {
                if (WORDLE_WORDS.get(i).toLowerCase().contains(String.valueOf(ALHPHABET[j]))) {
                    if (frequency.containsKey(ALHPHABET[j])) {
                        frequency.put(ALHPHABET[j], frequency.get(ALHPHABET[j]) + 1);
                    } else {
                        frequency.put(ALHPHABET[j], 1);
                    }
                }
            }
        }

        for (int i = 0; i < WORDLE_WORDS.toArray().length; i ++) {
            String word = WORDLE_WORDS.get(i).toLowerCase();
            int guess = 0;
            for (int j = 0; j < 5; j++) {
                if (word.substring(0, j).contains(String.valueOf(word.charAt(j)))) {
                    continue;
                }
                guess += frequency.get(word.charAt(j));
            }
            guessValue.put(guess, WORDLE_WORDS.get(i));
        }

        guessSortedValues = new ArrayList<>(guessValue.keySet());

        Collections.sort(guessSortedValues, Collections.reverseOrder());

    }

    public static String guess(Wordle wordle) {
        new Guesser();
//        return WORDLE_WORDS.get((int) (Math.random() * WORDLE_WORDS.toArray().length));
        return guessValue.get(guessSortedValues.get(0));
    }
}