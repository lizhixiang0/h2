package com.wangwenjun.concurrent.chapter15;

/**
 * @author admin
 * @description  观察任务执行期间状态并执行响应的方法。感觉没啥用。。。
 */
public class ObservableThreadTest {
    public static void main(String[] args) {
        TaskLifecycle<String> lifecycle = new TaskLifecycle.EmptyLifecycle<>();
        Task task = new Task.Default();

        Observable observableThread = new ObservableThread<>(lifecycle,task);
        observableThread.start();
    }
}
