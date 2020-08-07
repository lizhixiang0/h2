package com.zx.arch.topic;


import java.util.Arrays;
import java.util.List;

/**
 * TopicNames definition
 *
 * @author admin
 */
public interface TopicNames {

    String T_APP_SCAN_EVENT = "app";

    List<String> BIZ_TOPIC_NAME_LIST = Arrays.asList(
            T_APP_SCAN_EVENT
    );

    List<String> JSON_TOPIC_NAME_LIST = Arrays.asList(
    );
}
