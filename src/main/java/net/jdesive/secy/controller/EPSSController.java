package net.jdesive.secy.controller;

import net.jdesive.secy.service.EPSSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("epss")
public class EPSSController {

    private EPSSService epssService;

    @Autowired
    public EPSSController(EPSSService epssService) {
        this.epssService = epssService;
    }

    @GetMapping("ingest")
    public void ingest() {
        this.epssService.ingestEPSSData();
    }

}
