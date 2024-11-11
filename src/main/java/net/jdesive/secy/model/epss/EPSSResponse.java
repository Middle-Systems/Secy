package net.jdesive.secy.model.epss;

import lombok.Data;

import java.util.List;

@Data
public class EPSSResponse {

    private int total;

    private int offset;

    private int limit;

    private List<EPSSData> data;

}
