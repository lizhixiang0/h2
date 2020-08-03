package com.example.h2.rest;

import com.example.h2.bean.TestConverter;
import com.example.h2.kfk.message.UpdateApkFileMessage;
import com.example.h2.kfk.producer.AbstractKafkaGateway;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

/**
 * @author lizx
 * @date 2020/06/28
 **/
@Controller
@RequestMapping("/api")
public class Demo {

    @Autowired
    AbstractKafkaGateway abstractKafkaGateway;

    @GetMapping("/RestTemplate")
    @ResponseBody
    public String dds(){
        return "fuck";
    }

    @GetMapping("/hello")
    @ResponseBody
    public TestConverter dd(){
        TestConverter testConverter = new TestConverter();
        testConverter.setDate(new Date());
        return testConverter;
    }
    @GetMapping("/test")
    public TestConverter ddd(){
        TestConverter testConverter = new TestConverter();
        testConverter.setDate(new Date());
        return testConverter;
    }

    @GetMapping("/kfk")
    @ResponseBody
    public void sendMessage1() {
        UpdateApkFileMessage updateApkFileMessage = new UpdateApkFileMessage();
        updateApkFileMessage.setApkFileId(1L);
        updateApkFileMessage.setScanTaskId(1L);
        abstractKafkaGateway.send("app",updateApkFileMessage);
    }

}

