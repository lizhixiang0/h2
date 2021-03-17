package com.zx.arch.proxy.asm;

import com.alibaba.fastjson.util.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StreamUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.stream.Stream;

import static org.objectweb.asm.Opcodes.ASM4;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;

/**
 * 使用asm将TimeProxy的方法织入到Tank中
 * @author lizx
 * @since 1.0.0
 **/
public class ClassTransformerTest {

    private static final String TRUE_ROLE_NAME = "com.zx.arch.proxy.asm.Tank";

    private static final String TRUE_ROLE_CLASS = "com/zx/arch/proxy/asm/Tank.class";

    private static final String PROXY_ROLE_NAME = "com/zx/arch/proxy/asm/TimeProxy";

    private static final String TRUE_METHOD = "move";

    public static void main(String[] args) throws Exception {
        // 1、创建类读取器,将Tank类的二进制字节码作为参数传递过去
        ClassReader cr = new ClassReader(Objects.requireNonNull(ClassTransformerTest.class.getClassLoader().getResourceAsStream(TRUE_ROLE_CLASS)));
        // 2、创建类书写器
        ClassWriter cw = new ClassWriter(0);
        // 3、创建类观察器,将书写器作为参数传递进去
        ClassVisitor cv = new ClassVisitor(ASM4, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                // 创建方法参观器.每个方法都会调用这个
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (Objects.equals(name,TRUE_METHOD)){
                    return new MethodVisitor(ASM4, mv) {
                        @Override
                        public void visitCode() {
                            visitMethodInsn(INVOKESTATIC, PROXY_ROLE_NAME,"before", "()V", false);
                        }
                    };
                }else {
                    return  new MethodVisitor(ASM4, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                        }
                    };
                }

            }
        };

        cr.accept(cv, 0);


        // 上面已经使用asm将代码改完了，下面是将改完的内容从ClassWriter里拿出来
        // 将书写器的内容转化成二进制
        byte[] b2 = cw.toByteArray();
        // 创建自定义的类加载器
        ClassWriteTest.MyClassLoader classLoader = new ClassWriteTest.MyClassLoader();
        // 使用类加载器创建class对象
        Class c2 = classLoader.defineClass(TRUE_ROLE_NAME, b2);
        // 使用class创建对象
        Object o = c2.getConstructor().newInstance();
        // 调用move方法
        c2.getMethod("move").invoke(o);


        //将字节码写到类文件里去
        String fileName = Path.of(ClassTransformerTest.class.getResource("/").toURI())+"/com/zx/arch/proxy/asm/Tank_0.class";
        Files.write(Path.of(fileName),b2);
    }
}
