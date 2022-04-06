package com.sj;

import java.time.Instant;
import java.util.TimeZone;

public class TestMain {
    public static void main(String[] args) {
        Instant issuedAt = Instant.now();
        System.out.println(issuedAt);
        System.out.println(TimeZone.getDefault());
    }
}
