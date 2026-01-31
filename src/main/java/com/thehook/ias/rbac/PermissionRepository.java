package com.thehook.ias.rbac;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    Optional<Permission> findByKey(String key);

    boolean existsByKey(String key);

    @Query("SELECT p FROM Permission p ORDER BY p.key")
    List<Permission> findAllOrderByKey();
}
