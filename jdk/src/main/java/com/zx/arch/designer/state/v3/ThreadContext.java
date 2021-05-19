package com.zx.arch.designer.state.v3;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * @author lizx
 * @since 1.0.0
 **/
@Getter
@Setter
public class ThreadContext {
    private ThreadState threadState;

    public ThreadContext() {
        threadState=new NewState();
    }
    public void start(){
        threadState.start(this);
    }
    public void getCpu() {
        threadState.getCpu(this);
    }
    public void suspend() {
        threadState.suspend(this);
    }
    public void stop() {
        threadState.stop(this);
    }
    public void resume() {
        threadState.resume(this);
    }

    public static void main(String args []) {
            // 注意看一个小改变,这里我并没有传递状态进去（他自己有个初始状态，内部初始化了）,然后改变ThreadContext中的状态
            ThreadContext tc=new ThreadContext();
            tc.start();
            tc.getCpu();
            tc.suspend();

    }
}

