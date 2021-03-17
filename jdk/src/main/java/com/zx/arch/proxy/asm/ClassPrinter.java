package com.zx.arch.proxy.asm;
import org.objectweb.asm.*;
import java.io.IOException;
import java.util.Objects;
import static org.objectweb.asm.Opcodes.ASM4;

/**
 * 利用asm打印一个类的内部信息
 * @author lizx
 * @since 1.0.0
 **/
public class ClassPrinter extends ClassVisitor {
    public ClassPrinter() {
        super(ASM4);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        System.out.println(name + " extends " + superName + "{" );
    }

    @Override
    public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
        System.out.println("    " + name);
        return null;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        System.out.println("    " + name + "()");
        return null;
    }

    @Override
    public void visitEnd() {
        System.out.println("}");
    }

    public static void main(String[] args) throws IOException {
        // 1、构建一个类打印器
        ClassVisitor cp = new ClassPrinter();
        // 2、创建类阅读器cr1
        ClassReader cr1 = new ClassReader("java.lang.Runnable");
        // 3、将打印器作为参数传递给阅读器
        cr1.accept(cp, 0);

        // 打印自定义的类
        // 需要用应用类加载器来加载,不然找不到
        ClassReader cr2 = new ClassReader(Objects.requireNonNull(ClassPrinter.class.getClassLoader().getResourceAsStream("com/zx/arch/proxy/asm/Tank.class")));
        cr2.accept(cp, 0);
    }
}