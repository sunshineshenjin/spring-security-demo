package com.sj.oauth2.rs.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessageController {

    @GetMapping("/messages")
    public String[] getMessages() {
        return new String[] {"Message 1", "Message 2", "Message 3"};
    }

    @GetMapping("/test")
    public String[] test() {
        return new String[] {"Message 1", "Message 2", "Message 3"};
    }
}
