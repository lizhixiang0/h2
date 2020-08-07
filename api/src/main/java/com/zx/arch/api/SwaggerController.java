package com.zx.arch.api;

import com.zx.arch.web.ApiConstants;
import com.zx.arch.web.RestMessage;
import com.zx.arch.web.swagger.request.ScanTaskRequest;
import io.swagger.annotations.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

/**
 * @author lizx
 * @date 2020/08/06
 **/
@Api(value="【标题】",tags = "描述")
@Controller
@RequestMapping("/test")
public class SwaggerController {

    @PostMapping("/hello")
    @ResponseBody
    @ApiOperation(value="创建任务",notes = "注意id为必填项")
    @ApiResponses(value = {@ApiResponse(code = ApiConstants.HTTP_STATUS_OK,message = "success")})
    public RestMessage test(@RequestBody @ApiParam(value = "Created user object", required = true) ScanTaskRequest scanTaskRequest){
        RestMessage restMessage = new RestMessage();
        restMessage.setData(new Date());
        restMessage.setMessage(scanTaskRequest.toString());
        return restMessage;
    }

    @GetMapping("/hello/{phone}")
    @ResponseBody
    @ApiOperation(value="说明方法的用途",notes = "方法的备注说明")
    @ApiResponses({
            @ApiResponse(code = ApiConstants.HTTP_STATUS_OK,message = "success" ,response = RestMessage.class),
            @ApiResponse(code=ApiConstants.HTTP_STATUS_BAD_REQUEST,message="请求参数没填好"),
            @ApiResponse(code=ApiConstants.HTTP_STATUS_NOT_FOUND,message="请求路径没有或页面跳转路径不对")
    })
    public RestMessage test2(@PathVariable("phone") int phone){
        RestMessage restMessage = new RestMessage();
        restMessage.setData(new Date());
        restMessage.setMessage(String.valueOf(phone));
        return restMessage;
    }

    @PutMapping("/hello")
    @ResponseBody
    @ApiImplicitParam(name="name",value="名字",required=true,paramType="header",dataType="String",defaultValue = "head china cant solve")
    @ApiOperation(value="测试@ApiImplicitParam注解",notes = "putMapping一般用于修改")
    public RestMessage test3(String name){
        RestMessage restMessage = new RestMessage();
        restMessage.setMessage(name);
        return restMessage;
    }
    /*@RequestBody不能用@ApiImplicitParam注解没用。只能用@ApiParam*/
    /*@ApiImplicitParam注解里name必须和方法参数名相同*/
}
