package com.thehook.ias.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thehook.ias.common.exception.IasException;
import com.thehook.ias.user.UserService;
import com.thehook.ias.user.dto.RegisterRequest;
import com.thehook.ias.user.dto.RegisterResponse;
import com.thehook.ias.user.dto.VerifyEmailResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthApiController.class)
@Import(TestSecurityConfig.class)
class AuthApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService userService;

    @MockBean
    private JwtDecoder jwtDecoder;

    @Nested
    @DisplayName("POST /auth/register")
    class RegisterTests {

        @Test
        @DisplayName("should register user successfully")
        void shouldRegisterUser() throws Exception {
            UUID userId = UUID.randomUUID();
            RegisterRequest request = new RegisterRequest("test@example.com", "Password123", "Test User");
            RegisterResponse response = RegisterResponse.of(userId, "test@example.com", "Test User", "verification-token");

            when(userService.registerUser(any(RegisterRequest.class), anyString())).thenReturn(response);

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.userId").value(userId.toString()))
                    .andExpect(jsonPath("$.email").value("test@example.com"))
                    .andExpect(jsonPath("$.displayName").value("Test User"))
                    .andExpect(jsonPath("$.emailVerified").value(false))
                    .andExpect(jsonPath("$.verificationToken").value("verification-token"))
                    .andExpect(jsonPath("$.message").exists());
        }

        @Test
        @DisplayName("should return 400 for invalid email")
        void shouldReturn400ForInvalidEmail() throws Exception {
            String invalidRequest = """
                    {
                        "email": "not-an-email",
                        "password": "Password123",
                        "displayName": "Test User"
                    }
                    """;

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(invalidRequest))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("should return 400 for missing email")
        void shouldReturn400ForMissingEmail() throws Exception {
            String invalidRequest = """
                    {
                        "password": "Password123",
                        "displayName": "Test User"
                    }
                    """;

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(invalidRequest))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("should return 400 for short password")
        void shouldReturn400ForShortPassword() throws Exception {
            String invalidRequest = """
                    {
                        "email": "test@example.com",
                        "password": "short",
                        "displayName": "Test User"
                    }
                    """;

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(invalidRequest))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("should return 400 for missing display name")
        void shouldReturn400ForMissingDisplayName() throws Exception {
            String invalidRequest = """
                    {
                        "email": "test@example.com",
                        "password": "Password123"
                    }
                    """;

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(invalidRequest))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("should return 409 for duplicate email")
        void shouldReturn409ForDuplicateEmail() throws Exception {
            RegisterRequest request = new RegisterRequest("existing@example.com", "Password123", "Test User");

            when(userService.registerUser(any(RegisterRequest.class), anyString()))
                    .thenThrow(IasException.conflict("Email already registered"));

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isConflict());
        }
    }

    @Nested
    @DisplayName("POST /auth/verify")
    class VerifyEmailPostTests {

        @Test
        @DisplayName("should verify email successfully")
        void shouldVerifyEmail() throws Exception {
            UUID userId = UUID.randomUUID();
            VerifyEmailResponse response = VerifyEmailResponse.success(userId, "test@example.com");

            when(userService.verifyEmailWithResponse("valid-token")).thenReturn(response);

            mockMvc.perform(post("/auth/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"token\": \"valid-token\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(userId.toString()))
                    .andExpect(jsonPath("$.email").value("test@example.com"))
                    .andExpect(jsonPath("$.emailVerified").value(true))
                    .andExpect(jsonPath("$.message").exists());
        }

        @Test
        @DisplayName("should return 400 for invalid token")
        void shouldReturn400ForInvalidToken() throws Exception {
            when(userService.verifyEmailWithResponse("invalid-token"))
                    .thenThrow(IasException.badRequest("Invalid verification token"));

            mockMvc.perform(post("/auth/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"token\": \"invalid-token\"}"))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("should return 400 for expired token")
        void shouldReturn400ForExpiredToken() throws Exception {
            when(userService.verifyEmailWithResponse("expired-token"))
                    .thenThrow(IasException.badRequest("Verification token has expired"));

            mockMvc.perform(post("/auth/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"token\": \"expired-token\"}"))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("should return 400 for missing token")
        void shouldReturn400ForMissingToken() throws Exception {
            mockMvc.perform(post("/auth/verify")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("GET /auth/verify")
    class VerifyEmailGetTests {

        @Test
        @DisplayName("should verify email via GET with token parameter")
        void shouldVerifyEmailViaGet() throws Exception {
            UUID userId = UUID.randomUUID();
            VerifyEmailResponse response = VerifyEmailResponse.success(userId, "test@example.com");

            when(userService.verifyEmailWithResponse("valid-token")).thenReturn(response);

            mockMvc.perform(get("/auth/verify")
                            .param("token", "valid-token"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.emailVerified").value(true));
        }

        @Test
        @DisplayName("should return 400 for missing token parameter")
        void shouldReturn400ForMissingTokenParam() throws Exception {
            mockMvc.perform(get("/auth/verify"))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("POST /auth/resend-verification")
    class ResendVerificationTests {

        @Test
        @DisplayName("should resend verification email")
        void shouldResendVerification() throws Exception {
            when(userService.resendVerificationEmail("test@example.com")).thenReturn("new-token");

            mockMvc.perform(post("/auth/resend-verification")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\": \"test@example.com\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Verification email sent"))
                    .andExpect(jsonPath("$.verificationToken").value("new-token"));
        }

        @Test
        @DisplayName("should return 404 for unknown email")
        void shouldReturn404ForUnknownEmail() throws Exception {
            when(userService.resendVerificationEmail("unknown@example.com"))
                    .thenThrow(IasException.notFound("User", "unknown@example.com"));

            mockMvc.perform(post("/auth/resend-verification")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\": \"unknown@example.com\"}"))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("should return 400 if email already verified")
        void shouldReturn400IfAlreadyVerified() throws Exception {
            when(userService.resendVerificationEmail("verified@example.com"))
                    .thenThrow(IasException.badRequest("Email is already verified"));

            mockMvc.perform(post("/auth/resend-verification")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\": \"verified@example.com\"}"))
                    .andExpect(status().isBadRequest());
        }
    }
}
