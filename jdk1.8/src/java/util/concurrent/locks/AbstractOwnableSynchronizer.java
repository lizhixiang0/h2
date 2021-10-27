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
 * һ��ͬ�����������Ա�һ���̶߳�ռ
 * This class provides a basis for creating locks and related synchronizers that may entail a notion of ownership.
 * ������ṩ�˴����������ͬ�����Ļ�������Щͬ����������Ҫ����Ȩ�ĸ���
 * The {@code AbstractOwnableSynchronizer} class itself does not manage or use this information.
 * AbstractOwnableSynchronizer�౾���������ʹ�ô���Ϣ
 * However, subclasses and tools may use appropriately maintained values to help control and monitor access and provide diagnostics.
 * ���ǣ�����͹��߿���ʹ���ʵ�ά����ֵ���������ƺͼ��ӷ��ʲ��ṩ���
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
     * ��ռģʽ��ǰ�������̡߳�
     */
    private transient Thread exclusiveOwnerThread;

    /**
     * Sets the thread that currently owns exclusive access.
     * ���õ�ǰӵ�ж�ռ����Ȩ���߳�
     * A {@code null} argument indicates that no thread owns access.
     * null������ʾû���߳�ӵ�з���Ȩ��
     * This method does not otherwise impose any synchronization or {@code volatile} field accesses.
     * �˷�������ִ��ͬ����volatile�ֶη���
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
