package com.zx.arch.api;

import com.zx.arch.domain.entity.User;
import com.zx.arch.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    UserService userService;

    @GetMapping("/test")
    @ResponseBody
    public String a(){
        User user = userService.getUserById(1L);
        System.out.println(user);
        return "s";
    }
}
