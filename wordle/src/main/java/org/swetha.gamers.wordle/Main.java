// TODO(rass-scavenger): File path "/tmp/clone15861756571544415501/wordle/src/main/java/org/swetha.gamers.wordle" should match package name "org.swetha.gamers.wordle". Move the file to the correct directory structure (org/swetha/gamers/wordle/) or rename the directory to not use dots.
package org.swetha.gamers.wordle;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.ComponentScan;

import java.util.TimeZone;

@SpringBootApplication
@ComponentScan("org.swetha.gamers")
public class Main {
    public static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));

        ConfigurableApplicationContext context = SpringApplication.run(Main.class, args);
        context.registerShutdownHook();
    }
}