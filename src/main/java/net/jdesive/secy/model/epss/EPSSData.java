package net.jdesive.secy.model.epss;

import lombok.Data;

@Data
public class EPSSData {

    private String cve;

    private float epss;

    private float percentile;

}
