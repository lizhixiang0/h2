package com.zx.arch.api;

import com.zx.arch.web.ApiConstants;
import com.zx.arch.web.RestMessage;
import com.zx.arch.web.swagger.request.ScanTaskRequest;
import io.swagger.annotations.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.Random;

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

    //生成验证码图片
    @RequestMapping("/valicode.do") //对应/user/valicode.do请求
    public void valicode(HttpServletResponse response, HttpSession session) throws Exception{
        //利用图片工具生成图片
        //第一个参数是生成的验证码，第二个参数是生成的图片
        Object[] objs = ImageUtil.createImage();
        //将验证码存入Session
        session.setAttribute("imageCode",objs[0]);
        //将图片输出给浏览器
        BufferedImage image = (BufferedImage) objs[1];
        response.setContentType("image/png");
        OutputStream os = response.getOutputStream();
        ImageIO.write(image, "png", os);

    }

}
final class ImageUtil {

    // 验证码字符集
    private static final char[] chars = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    // 字符数量
    private static final int SIZE = 4;
    // 干扰线数量
    private static final int LINES = 5;
    // 宽度
    private static final int WIDTH = 80;
    // 高度
    private static final int HEIGHT = 40;
    // 字体大小
    private static final int FONT_SIZE = 30;

    /**
     * 生成随机验证码及图片
     * Object[0]：验证码字符串；
     * Object[1]：验证码图片。
     */
    public static Object[] createImage() {
        StringBuffer sb = new StringBuffer();
        // 1.创建空白图片
        BufferedImage image = new BufferedImage(
                WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
        // 2.获取图片画笔
        Graphics graphic = image.getGraphics();
        // 3.设置画笔颜色
        graphic.setColor(Color.LIGHT_GRAY);
        // 4.绘制矩形背景
        graphic.fillRect(0, 0, WIDTH, HEIGHT);
        // 5.画随机字符
        Random ran = new Random();
        for (int i = 0; i <SIZE; i++) {
            // 取随机字符索引
            int n = ran.nextInt(chars.length);
            // 设置随机颜色
            graphic.setColor(getRandomColor());
            // 设置字体大小
            graphic.setFont(new Font(
                    null, Font.BOLD + Font.ITALIC, FONT_SIZE));
            // 画字符
            graphic.drawString(
                    chars[n] + "", i * WIDTH / SIZE, HEIGHT*2/3);
            // 记录字符
            sb.append(chars[n]);
        }
        // 6.画干扰线
        for (int i = 0; i < LINES; i++) {
            // 设置随机颜色
            graphic.setColor(getRandomColor());
            // 随机画线
            graphic.drawLine(ran.nextInt(WIDTH), ran.nextInt(HEIGHT),
                    ran.nextInt(WIDTH), ran.nextInt(HEIGHT));
        }
        // 7.返回验证码和图片
        return new Object[]{sb.toString(), image};
    }

    /**
     * 随机取色
     */
    public static Color getRandomColor() {
        Random ran = new Random();
        Color color = new Color(ran.nextInt(256),
                ran.nextInt(256), ran.nextInt(256));
        return color;
    }

    public static void main(String[] args) throws IOException {
        Object[] objs = createImage();
        BufferedImage image = (BufferedImage) objs[1];
        OutputStream os = new FileOutputStream("d:/1.png");
        ImageIO.write(image, "png", os);
        os.close();
    }

}
