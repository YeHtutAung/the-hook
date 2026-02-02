package com.thehook.ias.auth;

import com.thehook.ias.user.UserService;
import com.thehook.ias.user.dto.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @Value("${ias.signup.enabled:true}")
    private boolean signupEnabled;

    @GetMapping("/login")
    public String loginPage(@RequestParam(required = false) String error,
                            @RequestParam(required = false) String logout,
                            Model model) {
        if (error != null) {
            model.addAttribute("error", "Invalid email or password");
        }
        if (logout != null) {
            model.addAttribute("message", "You have been logged out");
        }
        model.addAttribute("signupEnabled", signupEnabled);
        return "login";
    }

    @GetMapping("/register")
    public String registerPage(Model model) {
        if (!signupEnabled) {
            return "redirect:/login";
        }
        model.addAttribute("registerRequest", new RegisterFormData());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("registerRequest") RegisterFormData formData,
                          BindingResult bindingResult,
                          HttpServletRequest request,
                          RedirectAttributes redirectAttributes,
                          Model model) {
        if (!signupEnabled) {
            return "redirect:/login";
        }
        if (bindingResult.hasErrors()) {
            return "register";
        }

        try {
            RegisterRequest registerRequest = new RegisterRequest(
                    formData.getEmail(),
                    formData.getPassword(),
                    formData.getDisplayName()
            );
            userService.register(registerRequest, request.getRemoteAddr());

            redirectAttributes.addFlashAttribute("message",
                    "Registration successful! Please check your email to verify your account.");
            return "redirect:/login";
        } catch (Exception e) {
            log.error("Registration failed", e);
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam String token, RedirectAttributes redirectAttributes) {
        try {
            userService.verifyEmail(token);
            redirectAttributes.addFlashAttribute("message", "Email verified successfully! You can now log in.");
        } catch (Exception e) {
            log.error("Email verification failed", e);
            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/login";
    }

    // Form data class for Thymeleaf binding
    @lombok.Data
    public static class RegisterFormData {
        @jakarta.validation.constraints.NotBlank(message = "Email is required")
        @jakarta.validation.constraints.Email(message = "Invalid email format")
        private String email;

        @jakarta.validation.constraints.NotBlank(message = "Password is required")
        @jakarta.validation.constraints.Size(min = 8, message = "Password must be at least 8 characters")
        private String password;

        @jakarta.validation.constraints.NotBlank(message = "Display name is required")
        private String displayName;
    }
}
