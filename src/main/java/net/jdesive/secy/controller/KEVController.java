package net.jdesive.secy.controller;

import net.jdesive.secy.service.KEVService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("kev")
public class KEVController {

    private final KEVService kevService;

    @Autowired
    public KEVController(KEVService kevService) {
        this.kevService = kevService;
    }

    @GetMapping("ingest")
    public void ingest() {
        this.kevService.ingest();
    }

}
