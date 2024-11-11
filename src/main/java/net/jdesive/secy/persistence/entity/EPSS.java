package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Entity
@Table(name = "epss")
public class EPSS {

    @Id
    private String cve;

    private float epss;

    private float percentile;

}
