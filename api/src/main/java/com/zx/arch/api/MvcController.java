package com.zx.arch.api;

import com.zx.arch.rest.BaseController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import java.util.Date;

/**
 * @author lizx
 * @since 1.0.0
 **/
@Controller
@RequestMapping("/mvc")
public class MvcController extends BaseController {


    @GetMapping("/test")
    @ResponseBody
    public Date a(@RequestParam(name = "date") Date dateTime, @RequestParam("addr") String addr,@RequestParam("lastName") String lastName ){
        System.out.println(addr+lastName);
        // 这里注意下，其实我们在WebMvcConfig里配置了时间输出格式为yyyy-MM-dd,其实还可以配置时间输入格式。
        return dateTime;
    }

    //绑定变量名字和属性，参数封装进类
    @InitBinder("addr")
    public void initBinderAddr(WebDataBinder binder) {
        binder.setFieldDefaultPrefix("addr.");
    }

    @InitBinder("lastName")
    private void initBinder(WebDataBinder binder){
        //由表单到JavaBean赋值过程中哪一个值不进行赋值
        binder.setDisallowedFields("lastName");
    }


}
