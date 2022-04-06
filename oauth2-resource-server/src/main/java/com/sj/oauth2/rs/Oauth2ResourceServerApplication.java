package com.sj.oauth2.rs;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.sj")
public class Oauth2ResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2ResourceServerApplication.class, args);
    }

}
