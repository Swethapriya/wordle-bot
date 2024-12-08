package org.swetha.gamers.wordle.service;


import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.swetha.gamers.wordle.resources.Letter;
import org.swetha.gamers.wordle.resources.WORD;
import org.swetha.gamers.wordle.resources.Wordle;

import java.util.*;

import static org.swetha.gamers.wordle.resources.Constants.ALHPHABET;
import static org.swetha.gamers.wordle.resources.Constants.WORDLE_WORDS;

public class Guesser {
    public HashMap<Character, Integer> frequency;
    //TODO debug this, guessValue won't allow multiple strings.
    public static HashMap<Integer, ArrayList<String>> guessValue;
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
            if (guessValue.containsKey(guess)) {
                guessValue.get(guess).add(WORDLE_WORDS.get(i));
            } else {
                guessValue.put(guess, new ArrayList<>(Arrays.asList(WORDLE_WORDS.get(i))));
            }
        }
        guessSortedValues = new ArrayList<>(guessValue.keySet());
        Collections.sort(guessSortedValues, Collections.reverseOrder());

    }

    public static String guess(Wordle wordle) {
        new Guesser();
        String suggest = "";
        HashMap<Character, Letter> SOLUTION_ALPHABET = new HashMap<>();
        HashMap<Character, Integer> MUST = new HashMap<>();
        if (ObjectUtils.isNotEmpty(wordle.getFirst())) {
            SOLUTION_ALPHABET = populate(wordle.getFirst(), SOLUTION_ALPHABET);
            MUST = populateMust(wordle.getFirst(), MUST);
        }
        if (ObjectUtils.isNotEmpty(wordle.getSecond())) {
            SOLUTION_ALPHABET = populate(wordle.getSecond(), SOLUTION_ALPHABET);
            MUST = populateMust(wordle.getFirst(), MUST);
        }
        if (ObjectUtils.isNotEmpty(wordle.getThird())) {
            SOLUTION_ALPHABET = populate(wordle.getThird(), SOLUTION_ALPHABET);
            MUST = populateMust(wordle.getFirst(), MUST);
        }
        if (ObjectUtils.isNotEmpty(wordle.getFourth())) {
            SOLUTION_ALPHABET = populate(wordle.getFourth(), SOLUTION_ALPHABET);
            MUST = populateMust(wordle.getFirst(), MUST);
        }
        if (ObjectUtils.isNotEmpty(wordle.getFifth())) {
            SOLUTION_ALPHABET = populate(wordle.getFifth(), SOLUTION_ALPHABET);
            MUST = populateMust(wordle.getFirst(), MUST);
        }

        for (int i = 0; i < guessSortedValues.size(); i++) {
            for (int j = 0; j < guessValue.get(guessSortedValues.get(i)).size(); j++){
                suggest = guessValue.get(guessSortedValues.get(i)).get(j);
                if(isValidGuess(suggest.toLowerCase(), SOLUTION_ALPHABET, MUST)) {
                    return suggest;
                }
            }
        }

        return suggest;
    }

    private static HashMap<Character, Integer> populateMust(WORD guess, HashMap<Character, Integer> must) {
        char[] guess1 = guess.getWord();
        String[] color = guess.getColor();
        for (int i = 0 ; i < 5; i++) {
            char letter = guess1[i];
            String presence = color[i];
            if (StringUtils.equalsIgnoreCase(presence, "yellow")) {
                if (!must.containsKey(letter)) {
                    must.put(letter, -1);
                }
            } else if (StringUtils.equalsIgnoreCase(presence, "green")) {
                if (!must.containsKey(letter)) {
                    must.put(letter, i);
                }
            }
        }
        return must;
    }

    private static HashMap<Character, Letter> populate(WORD guess, HashMap<Character, Letter> solutionAlphabet) {
        char[] guess1 = guess.getWord();
        String[] color = guess.getColor();
        for (int i = 0 ; i < 5; i++) {
            int[] positions = new int[]{1, 2, 3, 4, 5};
            char letter = guess1[i];
            String presence = color[i];
            if (StringUtils.equalsIgnoreCase(presence, "grey")) {
                if (!solutionAlphabet.containsKey(letter)) {
                    solutionAlphabet.put(letter, new Letter(0, new int[]{}));
                }
            } else if (StringUtils.equalsIgnoreCase(presence, "yellow")) {
                int finalI = i;
                int[] possiblePositions = Arrays.stream(positions).filter(position -> position!= finalI+1).toArray();
                if (solutionAlphabet.containsKey(letter)) {
                    possiblePositions = Arrays.stream(solutionAlphabet.get(letter).getPositions())
                            .filter(position -> position!= finalI+1).toArray();
                    solutionAlphabet.put(letter, new Letter(1, possiblePositions));
                }
                solutionAlphabet.put(letter, new Letter(1, possiblePositions));
                //TODO handle duplicate letters in the guess.
            } else if (StringUtils.equalsIgnoreCase(presence, "green")) {
                solutionAlphabet.put(letter, new Letter(1, new int[]{i+1}));
            }
        }
        return solutionAlphabet;
    }

    private static boolean isValidGuess(String suggest, HashMap<Character, Letter> SOLUTION_ALPHABET, HashMap<Character, Integer> MUST) {
        for (int i = 0; i < 5; i++) {
            char letter = suggest.charAt(i);
            if (SOLUTION_ALPHABET.containsKey(letter)) {
                int[] validPositions = SOLUTION_ALPHABET.get(letter).getPositions();
                int finalI = i+1;
                boolean match = Arrays.stream(validPositions).anyMatch(x -> x == finalI);
                if (!match) {
                    return false;
                }
            }
        }
        Set<Character> mustKeys = MUST.keySet();
        for (char letter : mustKeys) {
            Integer position = MUST.get(letter);
            if (!suggest.contains(letter + "")) {
                return false;
            } else if (position != -1 && suggest.charAt(position - 1) != letter) {
                return false;
            }
        }

        return true;
    }
}