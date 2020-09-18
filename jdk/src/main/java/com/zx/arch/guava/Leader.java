package com.zx.arch.guava;

import com.google.common.collect.Maps;

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
     * study log
     */
    default void setLogs() {
        Basic_Utilities_logs.put("ͨ��Optional������ʹ�û��߱���null", "http://ifeve.com/google-guava-using-and-avoiding-null/");
        Basic_Utilities_logs.put("Preconditions�����ṩ������ǰ�������жϵ�ʵ�÷���","http://ifeve.com/google-guava-preconditions/");
        Basic_Utilities_logs.put("Guava��д�˳�����Object����","http://ifeve.com/google-guava-commonobjectutilities/");
    }


}
