package net.jdesive.secy.controller;

import net.jdesive.secy.persistence.entity.KEV;
import net.jdesive.secy.service.KEVService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("kev")
public class KEVController {

    private final KEVService kevService;

    @Autowired
    public KEVController(KEVService kevService) {
        this.kevService = kevService;
    }

    @GetMapping
    public Page<KEV> getKevEntries(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size,
            @RequestParam(required = false) String search) {
        return kevService.getPagedKev(page, size, search);
    }

    @GetMapping("ingest")
    public void ingest() {
        this.kevService.ingest();
    }

}
