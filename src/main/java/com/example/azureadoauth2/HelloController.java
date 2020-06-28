package com.example.azureadoauth2;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/azuread")
    @PreAuthorize("hasRole('Reader')")
    public String azureAD() {
        return "Hello AzureAD";
    }
}
