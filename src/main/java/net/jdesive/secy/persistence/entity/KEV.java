package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity
@Table(name = "kev")
public class KEV {

    @Id
    private String cveId;

    private String vendor;

    private String product;

    private String name;

    private Date added;

    @Column(length = 1024)
    private String description;

    @Column(length = 1024)
    private String requiredActions;

    private Date dueDate;

    private String knownRansomwareCampaignUse;

    @Column(length = 1024)
    private String notes;

}
