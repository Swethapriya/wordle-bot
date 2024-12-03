package org.swetha.gamers.wordle.service;


import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.swetha.gamers.wordle.resources.Answer;
import org.swetha.gamers.wordle.resources.Letter;
import org.swetha.gamers.wordle.resources.Wordle;

import java.util.*;

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
        HashMap<Character, Letter> SOLUTION_ALPHABET = new HashMap<>();
//        return WORDLE_WORDS.get((int) (Math.random() * WORDLE_WORDS.toArray().length));
        if (ObjectUtils.isNotEmpty(wordle.getFirst())) {
            char[] guess1 = wordle.getFirst().getWord();
            String[] color = wordle.getFirst().getColor();
            for (int i = 0 ; i < 5; i++) {
                int[] positions = new int[]{1, 2, 3, 4, 5};
                char letter = guess1[i];
                String presence = color[i];
                if (StringUtils.equalsIgnoreCase(presence, "grey")) {
                    if (!SOLUTION_ALPHABET.containsKey(letter)) {
                        SOLUTION_ALPHABET.put(letter, new Letter(0, new int[]{}));
                    }
                } else if (StringUtils.equalsIgnoreCase(presence, "yellow")) {
                    int finalI = i;
                    int[] possiblePositions = Arrays.stream(positions).filter(position -> position!= finalI).toArray();
                    if (!SOLUTION_ALPHABET.containsKey(letter)) {
                        SOLUTION_ALPHABET.put(letter, new Letter(1, possiblePositions));
                    } else {
                      //TODO
                    }
                }

            }
        }
        return guessValue.get(guessSortedValues.get(0));
    }
}