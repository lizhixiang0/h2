package com.zx.arch.api;

import com.zx.arch.domain.entity.User;
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
    public Date a(@RequestParam Date dateTime, @ModelAttribute("user") User user){
        System.out.println(user);
        // 这里注意下，其实我们在WebMvcConfig里配置了时间输出格式为yyyy-MM-dd,其实还可以配置时间输入格式。
        return dateTime;
    }

    /**
     * Controller级别的属性编辑器,
     * @param binder
     */
    @InitBinder("user")
    public void initBinderAddr(WebDataBinder binder) {
        // 设置所有变量名都可以加前缀addr,例如原来是name:lizx ，现在可以改写成addr.name:lizx
        binder.setFieldDefaultPrefix("addr.");
        // 设置哪一个值不进行赋值 ,即使前端传递了age这个属性，也不会set进对象
        binder.setDisallowedFields("age");
    }

}
