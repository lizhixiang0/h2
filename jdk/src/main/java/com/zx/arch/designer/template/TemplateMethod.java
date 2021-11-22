package com.zx.arch.designer.template;

/**
 * @author lizx
 * @date 2021/11/17
 * @since
 **/
public class TemplateMethod {
    public void print(){
        System.out.println("开头");
        wrapPrint();
        System.out.println("结尾");
    }

    protected void wrapPrint(){

    }

    public static void main(String[] args) {
        String str = "i am a pig";
        // 父类编写算法结构代码,子类实现逻辑
        TemplateMethod templateMethod = new TemplateMethod() {
            @Override
            protected void wrapPrint() {
                System.out.println(str);
            }
        };

        templateMethod.print();

    }
}
