package com.zx.arch.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author lizx
 * @date 2020/08/07
 * @description 用来测试spring、springboot特性
 **/
@Controller
@RequestMapping("/api")
public class CommonController {

    @GetMapping("/test")
    @ResponseBody
    public String a(){

        return "s";
    }
}
