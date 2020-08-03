package com.example.h2.rest;

import com.example.h2.bean.TestConverter;
import com.example.h2.bean.User;
import io.swagger.annotations.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import sun.awt.SunHints;

import java.util.Date;

/**
 * @author lizx
 * @date 2020/07/27
 **/
// Value:名字 tags:描述
@Api( value="【SwaggerTest】",tags = "测试swagger")
@Controller
@RequestMapping("/test")
public class SwaggerTest {

    @GetMapping("/hello")
    @ResponseBody
    @ApiOperation(value="说明方法的用途，例如:用户注册",notes = "方法的备注说明,例如:姓名是必填项")
    @ApiImplicitParams({
            @ApiImplicitParam(name="mobile",value="手机号",required=true,paramType="form"),
    })
    @ApiResponses(value = {@ApiResponse(code = ApiConstants.HTTP_STATUS_OK,message = "success")})
    public TestConverter dd(@RequestBody @ApiParam(value = "Created user object", required = true) User user){
        TestConverter testConverter = new TestConverter();
        testConverter.setDate(new Date());
        return testConverter;
    }

    @GetMapping("/hello/{s}")
    @ResponseBody
    @ApiOperation(value="说明方法的用途",notes = "方法的备注说明")
    @ApiImplicitParam(name="string",value="字符串",required=true,paramType="path",dataType="Integer",defaultValue="2")
    @ApiResponses({
            @ApiResponse(code = ApiConstants.HTTP_STATUS_OK,message = "success" ,response = TestConverter.class),
            @ApiResponse(code=ApiConstants.HTTP_STATUS_BAD_REQUEST,message="请求参数没填好"),
            @ApiResponse(code=ApiConstants.HTTP_STATUS_NOT_FOUND,message="请求路径没有或页面跳转路径不对")
    })
    public Integer d1(@PathVariable("s") int s){
        return s;
    }
}
