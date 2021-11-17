export {
    fetchUserNotificationMsgStats,
    downloadNotificationAttachment,
    resetUserNotificationRefreshInterval
}
    from "./actions";

export {
    fetchUserNotificationMsgStatsInitState,
    fetchUserNotificationMsgStatsReducer
}
    from "./reducers";

export const DEFAULT_REFRESH_INTERVAL = 3 * 1000 * 60; // 3 minutes

export const MessageListModes = {
    ALL: { key: 0, label: "label_all" },
    UNREAD: { key: 1, label: "left_menu_notification_unread" },
    READ: { key: 2, label: "left_menu_notification_read" }
};

export const MessageCategories = {
    ALL: { key: 0, label: "label_all" },
    SYSTEM: { key: 1, label: "label_ntf_msg_cat_system" },
    SUBSCRIPTION: { key: 2, label: "label_ntf_msg_cat_watched" },
    ALERT: { key: 3, label: "label_ntf_msg_cat_alert" },
    ACTIVITY: { key: 4, label: "label_ntf_msg_cat_activity" },
    GO_INSIGHT: { key: 5, label: "label_ntf_msg_cat_goinsight"},
    Announcement: { key: 6, label: "label_ntf_msg_cat_announcement"}
};

export const MessageTypes = {
    // Platform related (1-20)
    Sys_Platform_Notification: { key: 1, label: "label_ntf_msg_type_sys_pf_ntf", desc: "label_ntf_msg_type_sys_pf_ntf_desc" },

    // User(including Developer) related (21-40)
    Sys_Developer_Status_Update: { key: 21, label: "label_ntf_msg_type_sys_developer_status_update", desc: "label_ntf_msg_type_sys_developer_status_update_desc" },
    Sys_Developer_App_Status_Update: { key: 22, label: "label_ntf_msg_type_sys_developer_app_status_update", desc: "label_ntf_msg_type_sys_developer_app_status_update_desc" },
    Sys_Firmware_Status_Update: { key: 23, label: "label_ntf_msg_type_sys_firmware_status_update", desc: "label_ntf_msg_type_sys_firmware_status_update_desc" },
    Sys_Sandbox_Terminal_Update: { key: 24, label: "label_ntf_msg_type_sys_sandbox_terminal_update", desc: "label_ntf_msg_type_sys_sandbox_terminal_update_desc"},

    // Market Administrator related (41-70)
    Sys_Market_Status_Update: { key: 31, label: "label_ntf_msg_type_sys_market_status_update", desc: "label_ntf_msg_type_sys_market_status_update_desc" },
    Sys_Task_Audit_Developer: { key: 41, label: "label_ntf_msg_type_task_audit_developer", desc: "label_ntf_msg_type_task_audit_developer_desc" },
    Sys_Task_Audit_App: { key: 42, label: "label_ntf_msg_type_task_audit_app", desc: "label_ntf_msg_type_task_audit_app_desc" },
    Sys_Task_Audit_Firmware: { key: 43, label: "label_ntf_msg_type_task_audit_firmware", desc: "label_ntf_msg_type_task_audit_firmware_desc" },
//  AppScan relate
    Sys_App_Scan_Status_Update: { key: 51, label: "label_ntf_msg_type_app_scan_status_update", desc: "label_ntf_msg_type_app_scan_status_update_desc"},
    Sys_App_Scan_Engine_Update: { key: 52, label: "label_ntf_msg_type_app_scan_engine_update", desc: "label_ntf_msg_type_app_scan_engine_update_desc"},
    // Operation related (71-100)
    Sys_Op_Async_Import_Export_Result: { key: 71, label: "label_ntf_msg_type_op_async_import_export_result", desc: "label_ntf_msg_type_op_async_import_export_result_desc" },
    // Sys_Op_App_Specific_Distribution: { key: 71, label: "label_ntf_msg_type_op_app_specific_distribution", desc: "label_ntf_msg_type_op_app_specific_distribution_desc"},
    // Sys_Op_Firmware_Specific_Distribution: { key: 72, label: "label_ntf_msg_type_op_firmware_specific_distribution", desc: "label_ntf_msg_type_op_firmware_specific_distribution_desc"},
    // Sys_Op_App_Subscription: { key: 73, label: "label_ntf_msg_type_op_app_subscription", desc: "label_ntf_msg_type_op_app_subscription_desc"},
    // Sys_Op_Firmware_Subscription: { key: 74, label: "label_ntf_msg_type_op_firmware_subscription", desc: "label_ntf_msg_type_op_firmware_subscription_desc"},
    //Sys_Op_Report_Export_Result: { key: 81, label: "label_ntf_msg_type_op_report_export_result", desc: "label_ntf_msg_type_op_report_export_result_desc", readOnly: {email:true}},

    // // Subscription(watch) (100-150)
    Subscription_App_Status_Update: { key: 101, label: "label_ntf_msg_type_watched_app_status", desc: "label_ntf_msg_type_watched_app_status_desc" },
    Subscription_Firmware_Status_Update: { key: 102, label: "label_ntf_msg_type_watched_firmware_status", desc: "label_ntf_msg_type_watched_firmware_status_desc" },

    Alert_App_Signature: { key: 151, label: "label_app_signature", desc: "label_ntf_msg_type_alert_app_sign_desc" },
    Alert_RKI: { key: 152, label: "label_ntf_msg_type_alert", desc: "label_ntf_msg_type_alert" },
    Alert_Terminal_Out_Of_Range: { key: 153, label: "label_out_of_fence", desc: "label_terminal_out_of_range_alert_desc" },
    Alert_Terminal_Print_Out_Of_Paper: {key: 154, label: "label_printer_out_of_paper", desc: "label_terminal_print_out_of_paper_alert"},

    GoInsight_Plan_Notification_ALL: {key: 201, label: "label_insight_plan_notification", desc: "label_insight_plan_notification_desc"},
    GoInsight_Plan_Notification: {key: 202, label: "label_insight_plan_notification", desc: "label_insight_plan_notification_desc"},

    Others: { key: 0, label: "label_ntf_msg_type_others", desc: "label_ntf_msg_type_others_desc" }
};

export const MessageTypes_Activity = [
    MessageTypes.Sys_Task_Audit_Developer,
    MessageTypes.Sys_Task_Audit_App,
    MessageTypes.Sys_Task_Audit_Firmware,
    MessageTypes.Sys_Op_Async_Import_Export_Result
];

export const MessageTypes_System = [
    MessageTypes.Sys_Platform_Notification,
    MessageTypes.Sys_Market_Status_Update,
    MessageTypes.Sys_Developer_Status_Update,
    MessageTypes.Sys_Developer_App_Status_Update,
    MessageTypes.Sys_Firmware_Status_Update,
    MessageTypes.Sys_Sandbox_Terminal_Update,
    MessageTypes.Sys_App_Scan_Status_Update,
    MessageTypes.Sys_App_Scan_Engine_Update
];

export const MessageTypes_Watch = [
    MessageTypes.Subscription_App_Status_Update,
    MessageTypes.Subscription_Firmware_Status_Update
];

export const MessageTypes_Alert = [
    MessageTypes.Alert_App_Signature,
    MessageTypes.Alert_Terminal_Out_Of_Range,
    MessageTypes.Alert_Terminal_Print_Out_Of_Paper,
];

export const TopicCategories = {
    App: { key: 1 },
    Firmware_Model: { key: 2 }
};

export const getMessageTypeLabelKey = (type) => {
    let msgTypeLabelKey;
    let msgTypeKeys = Object.keys(MessageTypes);
    for (let key in msgTypeKeys) {
        if (type === MessageTypes[msgTypeKeys[key]].key) {
            msgTypeLabelKey = MessageTypes[msgTypeKeys[key]].label;
            break;
        }
    }
    if (!msgTypeLabelKey) {
        msgTypeLabelKey = MessageTypes.Others.label;
    }

    return msgTypeLabelKey;
};

export NotificationReminder from "./NotificationReminder";
