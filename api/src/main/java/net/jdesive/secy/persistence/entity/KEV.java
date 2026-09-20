package net.jdesive.secy.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
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

    private LocalDateTime added;

    // Free-text prose from the CISA feed, no documented length cap (see Liquibase 012 — a real
    // ingest overflowed varchar(1024) on requiredActions). columnDefinition, not @Column(length=),
    // since these map to `text` in Postgres and Hibernate's `length` is meaningless without it.
    @Column(columnDefinition = "text")
    private String description;

    @Column(columnDefinition = "text")
    private String requiredActions;

    private Date dueDate;

    private String knownRansomwareCampaignUse;

    @Column(columnDefinition = "text")
    private String notes;

}
