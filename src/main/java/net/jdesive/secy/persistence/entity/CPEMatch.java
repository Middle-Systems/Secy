package net.jdesive.secy.persistence.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.transaction.annotation.Transactional;

@Getter
@Setter
@ToString
@Entity
@Transactional
@Table(name = "cpe_match")
public class CPEMatch {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private boolean vulnerable;

    private String criteria;

    private String matchCriteriaId;

    @JsonIncludeProperties(value = {"id"})
    @ManyToOne(fetch = FetchType.LAZY)
    @ToString.Exclude
    private CPEOperator operator;

}
