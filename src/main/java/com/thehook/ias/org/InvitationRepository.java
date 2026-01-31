package com.thehook.ias.org;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface InvitationRepository extends JpaRepository<Invitation, UUID> {

    @Query("SELECT i FROM Invitation i " +
            "LEFT JOIN FETCH i.organization " +
            "LEFT JOIN FETCH i.role " +
            "WHERE i.token = :token")
    Optional<Invitation> findByToken(String token);

    boolean existsByOrganizationIdAndEmailAndStatus(UUID orgId, String email, InvitationStatus status);

    @Query("SELECT i FROM Invitation i " +
            "LEFT JOIN FETCH i.role " +
            "WHERE i.organization.id = :orgId AND i.status = :status " +
            "ORDER BY i.createdAt DESC")
    List<Invitation> findByOrganizationIdAndStatus(UUID orgId, InvitationStatus status);

    List<Invitation> findByEmailAndStatus(String email, InvitationStatus status);
}
