package com.zx.arch.designer.state.v3;

/**
 * 定义五种状态
 * @author lizx
 * @since 1.0.0
 **/
enum  StateSet {RUNNING,RUNNABLE,BLOCKED,NEW,DEAD}

/**
 * 将状态抽象出来,这里和小女孩的例子不一样，这里我把ThreadContext传递进去了，另外这里的方法并没有都实现
 */
public abstract class ThreadState {
    /**
     * 状态名
     */
    protected StateSet state;

    public void start(ThreadContext tc) {}

    public void suspend(ThreadContext tc) {}

    public void stop(ThreadContext tc) {}

    public void getCpu(ThreadContext tc) {}

    public void resume(ThreadContext tc) {}

}

class NewState extends ThreadState {
    public NewState() {
        state=StateSet.NEW;
        System.out.println("新建线程");
    }
    @Override
    public void start(ThreadContext tc) {
        System.out.println("调用了Start方法");
        if(state==StateSet.NEW) {
            tc.setThreadState(new RunnableState());
        } else {
            System.out.println("当前线程不是新建状态");
        }
    }
}
class RunningState extends ThreadState{
    public RunningState() {
        state=StateSet.RUNNING;
        System.out.println("运行状态");
    }
    @Override
    public void suspend(ThreadContext tc) {
        System.out.println("调用suspend方法");
        if(state==StateSet.RUNNING) {
            tc.setThreadState(new BlockedState());
        } else {
            System.out.println("当前状态不是运行状态");
        }
    }
    @Override
    public void stop(ThreadContext tc) {
        System.out.println("调用stop方法");
        if(state==StateSet.RUNNING) {
            tc.setThreadState(new DeadState());
        } else {
            System.out.println("当前状态不是运行状态");
        }
    }
}
class RunnableState extends ThreadState {
    public RunnableState() {
        state=StateSet.RUNNABLE;
        System.out.println("就绪状态");
    }

    @Override
    public void getCpu(ThreadContext tc) {
        // TODO Auto-generated method stub
        System.out.println("调用getCpu方法");
        if(state==StateSet.RUNNABLE) {
            tc.setThreadState(new RunningState());
        } else {
            System.out.println("当前状态不是就绪状态");
        }
    }
}
class BlockedState extends ThreadState {
    public BlockedState() {
        state=StateSet.BLOCKED;
        System.out.println("阻塞线程");
    }
    @Override
    public void resume(ThreadContext tc) {
        System.out.println("调用了resume方法");
        if(state==StateSet.BLOCKED) {
            tc.setThreadState(new RunnableState());
        } else {
            System.out.println("当前线程不是新建状态");
        }
    }
}
class DeadState extends ThreadState {
    public DeadState() {
        state=StateSet.DEAD;
        System.out.println("就绪状态");
    }

    @Override
    public void stop(ThreadContext tc) {
        // TODO Auto-generated method stub
        System.out.println("调用getCpu方法");
        if(state==StateSet.DEAD) {
            tc.setThreadState(new DeadState());
        } else {
            System.out.println("当前状态死亡");
        }
    }
}



