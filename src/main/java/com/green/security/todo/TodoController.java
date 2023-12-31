package com.green.security.todo;

import com.green.security.config.security.model.MyUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/todo-api")
public class TodoController {

    private final  TodoService SERVICE;

    @PostMapping
    public int insTodo(@AuthenticationPrincipal MyUserDetails user
            , @RequestParam String ctnt) {
        log.info("TodoController - insTodo: ctnt {}", ctnt);
        log.info("iuser {}", user.getIuser());
        SERVICE.test();
        return 1;
    }
}
