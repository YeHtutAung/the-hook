package com.thehook.ias.authorize;

import com.thehook.ias.authorize.dto.AuthorizeRequest;
import com.thehook.ias.authorize.dto.AuthorizeResponse;
import com.thehook.ias.org.Membership;
import com.thehook.ias.org.MembershipRepository;
import com.thehook.ias.rbac.Permission;
import com.thehook.ias.user.User;
import com.thehook.ias.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizeService {

    private final UserRepository userRepository;
    private final MembershipRepository membershipRepository;

    @Transactional(readOnly = true)
    public AuthorizeResponse authorize(AuthorizeRequest request) {
        log.debug("Authorization check: user={}, org={}, permission={}",
                request.userId(), request.orgId(), request.permissionKey());

        // Check if user exists and is enabled
        Optional<User> userOpt = userRepository.findById(request.userId());
        if (userOpt.isEmpty()) {
            log.debug("Authorization denied: user not found");
            return AuthorizeResponse.deny("User not found");
        }

        User user = userOpt.get();
        if (!user.isEnabled()) {
            log.debug("Authorization denied: user disabled");
            return AuthorizeResponse.deny("User is disabled");
        }

        // Platform owners have all permissions
        if (user.isPlatformOwner()) {
            log.debug("Authorization allowed: platform owner");
            return AuthorizeResponse.allow();
        }

        // Check membership and permissions
        Optional<Membership> membershipOpt = membershipRepository
                .findActiveByUserIdAndOrgId(request.userId(), request.orgId());

        if (membershipOpt.isEmpty()) {
            log.debug("Authorization denied: not a member of organization");
            return AuthorizeResponse.deny("Not a member of this organization");
        }

        Membership membership = membershipOpt.get();
        if (!membership.isActive()) {
            log.debug("Authorization denied: membership not active");
            return AuthorizeResponse.deny("Membership is not active");
        }

        // Check if any role has the required permission
        boolean hasPermission = membership.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .map(Permission::getKey)
                .anyMatch(key -> key.equals(request.permissionKey()));

        if (hasPermission) {
            log.debug("Authorization allowed: has permission");
            return AuthorizeResponse.allow();
        }

        log.debug("Authorization denied: missing permission");
        return AuthorizeResponse.deny("Missing required permission: " + request.permissionKey());
    }
}
