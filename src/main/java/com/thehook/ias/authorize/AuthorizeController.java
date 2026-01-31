package com.thehook.ias.authorize;

import com.thehook.ias.authorize.dto.AuthorizeRequest;
import com.thehook.ias.authorize.dto.AuthorizeResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/authorize")
@RequiredArgsConstructor
@Tag(name = "Authorization", description = "Central authorization API")
@SecurityRequirement(name = "oauth2")
public class AuthorizeController {

    private final AuthorizeService authorizeService;

    @PostMapping
    @Operation(
            summary = "Check permission",
            description = "Checks if a user has a specific permission within an organization. " +
                    "Used by other applications to make authorization decisions."
    )
    public AuthorizeResponse authorize(@Valid @RequestBody AuthorizeRequest request) {
        return authorizeService.authorize(request);
    }
}
