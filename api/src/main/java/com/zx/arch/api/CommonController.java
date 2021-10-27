package com.zx.arch.api;

import com.zx.arch.domain.entity.User;
import com.zx.arch.domain.service.UserService;
import com.zx.arch.spring.transaction.TransactionTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author lizx
 * @date 2020/08/07
 * @description 用来测试spring、springboot特性
 *
 **/
@Controller
@RequestMapping("/api")
public class CommonController {

    @Autowired
    UserService userService;

    @Autowired
    TransactionTest transactionTest;

    @GetMapping("/test")
    @ResponseBody
    //将请求精细化:https://www.cnblogs.com/lemonzhang/p/12925482.html
    public String a(){
        transactionTest.a();
        return "s";
    }




}
