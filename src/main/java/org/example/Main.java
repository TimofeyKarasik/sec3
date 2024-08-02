package org.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@EnableMethodSecurity
@SpringBootApplication
//@Import({ManualImplementation.class})
@Import({SpringImplementation.class})
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class,args);
    }
}