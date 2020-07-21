/**
 * ********************************************************************************
 * COPYRIGHT      
 *               PAX TECHNOLOGY, Inc. PROPRIETARY INFORMATION     
 *   This software is supplied under the terms of a license agreement or      
 *   nondisclosure agreement with PAX  Technology, Inc. and may not be copied     
 *   or disclosed except in accordance with the terms in that agreement.
 *         
 *      Copyright (C) 2018 PAX Technology, Inc. All rights reserved.
 * ********************************************************************************
 */

package com.example.h2.kfk.share.topic;

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
