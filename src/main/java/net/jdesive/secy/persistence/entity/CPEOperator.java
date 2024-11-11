package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@ToString
@Transactional
@Table(name = "cpe_operator")
public class CPEOperator {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String operator;

    private boolean negate;

    @OneToMany(mappedBy = "operator", cascade = CascadeType.ALL, orphanRemoval = true)
    @ToString.Exclude
    private List<CPEMatch> cpeMatches = new ArrayList<>();

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private Vulnerability cve;

}
