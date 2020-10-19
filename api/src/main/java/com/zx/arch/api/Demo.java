package com.zx.arch.api;



import com.zx.arch.domain.entity.TestConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


/**
 * @author lizx
 * @date 2020/06/28
 **/
@Controller
@RequestMapping("/api")
public class Demo {

    /*@Autowired
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
    @PostMapping ("/test")
    public TestConverter ddd( @RequestParam String s){
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
    }*/

}

