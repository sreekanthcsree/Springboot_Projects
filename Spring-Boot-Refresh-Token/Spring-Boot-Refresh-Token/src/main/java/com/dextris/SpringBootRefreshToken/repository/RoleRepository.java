package com.dextris.SpringBootRefreshToken.repository;

import com.dextris.SpringBootRefreshToken.models.ERole;
import com.dextris.SpringBootRefreshToken.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);
}
