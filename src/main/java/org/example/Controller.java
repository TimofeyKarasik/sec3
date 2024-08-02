package org.example;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {
    @GetMapping("/info")
    @PreAuthorize("hasRole('USER')")
    public String index(Authentication authentication) {
        return "INFO = " + authentication;
    }
}
