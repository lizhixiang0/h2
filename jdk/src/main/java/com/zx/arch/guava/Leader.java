package com.zx.arch.guava;

import com.google.common.collect.Maps;
import com.zx.arch.guava.BasicUtilities.*;
import com.zx.arch.guava.collections.UnmodifiableListTest;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description Guava���̰��������ɱ�Google�� Java��Ŀ�㷺���� �ĺ��Ŀ�
 **/
public interface Leader {
    /**
     * blog��ַ
     */
    String BLOG = "http://ifeve.com/google-guava/";
    /**
     * 1���������߰�
     */
    HashMap Basic_Utilities_logs = Maps.newHashMap();

    /**
     * 2�����Ϲ��߰�
     */
    HashMap Collections_logs = Maps.newHashMap();

    /**
     * study log
     */
    default void setBasicLogs() {
        Basic_Utilities_logs.put("ͨ��Optional������ʹ�û��߱���null", OptionalTest.class);
        Basic_Utilities_logs.put("Preconditions�����ṩ������ǰ�������жϵ�ʵ�÷���",PreconditionsTest.class);
        Basic_Utilities_logs.put("Guava��д�˳�����Object����",ObjectsTest.class);
        Basic_Utilities_logs.put("Guava�����ıȽ���", OrderingTest.class);
        Basic_Utilities_logs.put("���쳣�ʹ���Ĵ�������", ThrowableTest.class);
        Collections_logs.put("���ɱ伯��", UnmodifiableListTest.class);
    }


}
