/*
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */

/*
 *
 *
 *
 *
 *
 * Written by Doug Lea with assistance from members of JCP JSR-166
 * Expert Group and released to the public domain, as explained at
 * http://creativecommons.org/publicdomain/zero/1.0/
 */

package java.util.concurrent.locks;

/**
 * A synchronizer that may be exclusively owned by a thread.
 * 一个同步器，它可以被一个线程独占
 * This class provides a basis for creating locks and related synchronizers that may entail a notion of ownership.
 * 这个类提供了创建锁和相关同步器的基础，这些同步器可能需要所有权的概念
 * The {@code AbstractOwnableSynchronizer} class itself does not manage or use this information.
 * AbstractOwnableSynchronizer类本身并不管理或使用此信息
 * However, subclasses and tools may use appropriately maintained values to help control and monitor access and provide diagnostics.
 * 但是，子类和工具可以使用适当维护的值来帮助控制和监视访问并提供诊断
 * @since 1.6
 * @author Doug Lea
 */
public abstract class AbstractOwnableSynchronizer  implements java.io.Serializable {

    /** Use serial ID even though all fields transient. */
    private static final long serialVersionUID = 3737899427754241961L;

    /**
     * Empty constructor for use by subclasses.
     */
    protected AbstractOwnableSynchronizer() { }

    /**
     * The current owner of exclusive mode synchronization.
     * 独占模式当前所有者线程。
     */
    private transient Thread exclusiveOwnerThread;

    /**
     * Sets the thread that currently owns exclusive access.
     * 设置当前拥有独占访问权的线程
     * A {@code null} argument indicates that no thread owns access.
     * null参数表示没有线程拥有访问权限
     * This method does not otherwise impose any synchronization or {@code volatile} field accesses.
     * 此方法不会执行同步或volatile字段访问
     * @param thread the owner thread
     */
    protected final void setExclusiveOwnerThread(Thread thread) {
        exclusiveOwnerThread = thread;
    }

    /**
     * Returns the thread last set by {@code setExclusiveOwnerThread},or {@code null} if never set.
     * This method does not otherwise impose any synchronization or {@code volatile} field accesses.
     * @return the owner thread
     */
    protected final Thread getExclusiveOwnerThread() {
        return exclusiveOwnerThread;
    }
}
