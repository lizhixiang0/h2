package com.zx.arch.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @author lizx
 * @since 1.0.0
 **/
@Controller
public class HtmlController {

    @GetMapping("/html")
    public String test(){
        return "index";
    }
}
