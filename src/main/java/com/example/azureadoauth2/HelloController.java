package com.example.azureadoauth2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/azuread")
    public String azureAD() {
        return "Hello AzureAD";
    }
}
