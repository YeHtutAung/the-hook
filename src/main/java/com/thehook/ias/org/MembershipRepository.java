package com.thehook.ias.org;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface MembershipRepository extends JpaRepository<Membership, UUID> {

    @Query("SELECT m FROM Membership m " +
            "LEFT JOIN FETCH m.organization " +
            "LEFT JOIN FETCH m.roles " +
            "WHERE m.user.id = :userId AND m.status = 'ACTIVE'")
    List<Membership> findActiveByUserId(UUID userId);

    @Query("SELECT m FROM Membership m " +
            "LEFT JOIN FETCH m.roles r " +
            "LEFT JOIN FETCH r.permissions " +
            "WHERE m.user.id = :userId AND m.organization.id = :orgId AND m.status = 'ACTIVE'")
    Optional<Membership> findActiveByUserIdAndOrgId(UUID userId, UUID orgId);

    boolean existsByUserIdAndOrganizationId(UUID userId, UUID orgId);

    @Query("SELECT m FROM Membership m " +
            "LEFT JOIN FETCH m.user " +
            "LEFT JOIN FETCH m.roles " +
            "WHERE m.organization.id = :orgId AND m.status = 'ACTIVE'")
    List<Membership> findActiveByOrgId(UUID orgId);

    @Query("SELECT CASE WHEN COUNT(m) > 0 THEN true ELSE false END FROM Membership m JOIN m.roles r WHERE r.id = :roleId")
    boolean existsByRoleId(UUID roleId);
}
