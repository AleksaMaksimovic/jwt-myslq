package rs.gov.mup.jwtmyslq.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rs.gov.mup.jwtmyslq.model.ERole;
import rs.gov.mup.jwtmyslq.model.Role;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
