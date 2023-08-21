package com.green.security.todo;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/todo-api")
public class TodoController {

    @PostMapping
    public int insTodo(@RequestParam String ctnt) {
        log.info("TodoController - insTodo: ctnt {}", ctnt);

        return 1;
    }
}
