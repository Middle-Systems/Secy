package net.jdesive.secy.model.epss;

import lombok.Data;

import java.util.Date;

@Data
public class EPSSData {

    private String cve;

    private float epss;

    private float percentile;

    private Date date;

}
