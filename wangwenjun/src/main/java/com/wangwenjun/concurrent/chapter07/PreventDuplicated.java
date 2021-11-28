package com.wangwenjun.concurrent.chapter07;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * 钩子线程实战：防止程序被重复启动
 * 原理：服务启动时创建lock文件,服务关闭时删除lock文件,这样再次启动如果检测到有lock文件就说明是重复启动,不允许
 * @author admin
 */
public class PreventDuplicated {
    private final static String LOCK_PATH = "/home/wangwenjun/locks/";

    private final static String LOCK_FILE = ".lock";

    private final static String PERMISSIONS = "rw-------";

    public static void main(String[] args) throws IOException {

        // 检查是否存在lock文件,存在说明已经启动，抛出异常
        checkRunning();

        // 注入hook线程,在jvm退出时删除lock文件
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("The program received kill SIGNAL.");
            getLockFile().toFile().delete();
        }));

        // 模拟程序正在运行
        for (; ; ) {
            try {
                TimeUnit.MILLISECONDS.sleep(1);
                System.out.println("program is running.");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }


    }

    private static void checkRunning() throws IOException {
        Path path = getLockFile();

        if (path.toFile().exists()) {
            throw new RuntimeException("The program already running.");
        }

        Set<PosixFilePermission> perms = PosixFilePermissions.fromString(PERMISSIONS);
        Files.createFile(path, PosixFilePermissions.asFileAttribute(perms));
    }

    private static Path getLockFile() {
        return Paths.get(LOCK_PATH, LOCK_FILE);
    }
}
