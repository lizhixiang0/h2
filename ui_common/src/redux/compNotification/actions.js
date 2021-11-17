import {
    getApiInstance
} from "../../biz";
import handleError from "../error";
import {
    startAction,
    successAction,
    failureAction
} from "../../utils";
import { GLOBAL_MARKET_ID } from "../../biz/constants";
import { GLOBAL_LOADING_START, GLOBAL_LOADING_END } from "../../redux/loading/actionTypes";
import { GLOBAL_ERROR_MESSAGE_ACTION } from "../../redux/message/actionTypes";
import { handleDownloadResponse } from "../../redux/download/actions";

export const RESET_USER_NOTIFICATION_REFRESH_INTERVAL = "reset/user/notification/refreshInterval";
export const resetUserNotificationRefreshInterval = (newInterval, repeat) => {
    return dispatch => {
        dispatch({ type: startAction(RESET_USER_NOTIFICATION_REFRESH_INTERVAL) });
        dispatch({
            type: successAction(RESET_USER_NOTIFICATION_REFRESH_INTERVAL),
            payload: { newInterval, repeat }
        });
    };
};

export const FETCH_USER_NOTIFICATION_MSG_STATS = "fetch/user/notification/msg/stats";
export const fetchUserNotificationMsgStats = (clientId, marketId,callback) => {
    return dispatch => {
        dispatch({ type: startAction(FETCH_USER_NOTIFICATION_MSG_STATS) });
        getApiInstance().notification.getMessageStats().then(response => {
            dispatch({
                type: successAction(FETCH_USER_NOTIFICATION_MSG_STATS),
                payload: {
                    stats: response
                }
            });
            if (response && response.announcementInfos && response.announcementInfos.length > 0) {
                let announcementInfo = null;
                const announcementInfos = response.announcementInfos;
                switch (clientId) {
                    case "admin":
                        announcementInfo = announcementInfos.find(item => {
                            if (item.receiverType && (item.marketId == marketId || item.marketId == GLOBAL_MARKET_ID)) {
                                let arr = item.receiverType.split(",");
                                return (arr.includes('2') || arr.includes('3'))
                            }
                        });
                        break;
                    case "developer":
                        announcementInfo = announcementInfos.find(item => {
                            if (item.receiverType && item.marketId == marketId) {
                                let arr = item.receiverType.split(",");
                                return arr.includes('1')
                            }
                        });
                        break;
                    default:
                        announcementInfo = null;
                        break;
                }
                if (announcementInfo && announcementInfo['id']) {
                    dispatch(viewUserNotificationMsg(announcementInfo['id']));
                }
            }
            callback&&callback()
        }).catch(error => {
            handleError(dispatch, {
                type: failureAction(FETCH_USER_NOTIFICATION_MSG_STATS),
                payload: { error }
            }, error);
        });
    };
};

export const VIEW_USER_NOTIFICATION_MESSAGE = "stats/view/user/notification/message";
export const viewUserNotificationMsg = (messageId) => {
    return dispatch => {
        dispatch({ type: startAction(VIEW_USER_NOTIFICATION_MESSAGE) });
        getApiInstance().notification.viewMessage(messageId).then(response => {
            dispatch({
                type: successAction(VIEW_USER_NOTIFICATION_MESSAGE),
                payload: { response }
            });
        }).catch(error => {
            handleError(dispatch, {
                type: GLOBAL_ERROR_MESSAGE_ACTION,
                payload: {
                    message: error.message ? error.message : "err_msg_unknown_error",
                    className: "message_error"
                }
            }, error);
            handleError(dispatch, {
                type: failureAction(VIEW_USER_NOTIFICATION_MESSAGE),
                payload: { error }
            }, error);
        });
    };
};

export const CLEAR_USER_NOTIFICATION_MESSAGE = "stats/clear/user/notification/message";
export const clearUserNotificationMsg = () => {
    return dispatch => dispatch({ type: CLEAR_USER_NOTIFICATION_MESSAGE });
};

export const READ_USER_NOTIFICATION_MESSAGE = "stats/read/user/notification/message";
export const readNotificationMessage = (messageId) => {
    return dispatch => {
        dispatch({ type: startAction(READ_USER_NOTIFICATION_MESSAGE) });
        getApiInstance().notification.readMessage(messageId).then(response => {
            dispatch({
                type: successAction(READ_USER_NOTIFICATION_MESSAGE),
                payload: {
                    response
                }
            });
        }).catch(error => {
            handleError(dispatch, {
                type: GLOBAL_ERROR_MESSAGE_ACTION,
                payload: {
                    message: error.message ? error.message : "err_msg_unknown_error",
                    className: "message_error"
                }
            }, error);
            handleError(dispatch, {
                type: failureAction(READ_USER_NOTIFICATION_MESSAGE),
                payload: { error }
            }, error);
        });
    };
};

export const READ_USER_NOTIFICATION_TOPX_MESSAGES = "stats/read/user/notification/message/topx";
export const readNotificationTopXMessages = (messageIdList) => {
    return dispatch => {
        dispatch({ type: startAction(READ_USER_NOTIFICATION_TOPX_MESSAGES) });
        getApiInstance().notification.readTopXMessages(messageIdList).then(response => {
            dispatch({
                type: successAction(READ_USER_NOTIFICATION_TOPX_MESSAGES),
                payload: {
                    response
                }
            });
        }).catch(error => {
            handleError(dispatch, {
                type: GLOBAL_ERROR_MESSAGE_ACTION,
                payload: {
                    message: error.message ? error.message : "err_msg_unknown_error",
                    className: "message_error"
                }
            }, error);
            handleError(dispatch, {
                type: failureAction(READ_USER_NOTIFICATION_TOPX_MESSAGES),
                payload: { error }
            }, error);
        });
    };
};

export const DOWNLOAD_USER_NOTIFICATION_ATTACHMENT = "stats/download/user/notification/attachment";
export const downloadNotificationAttachment = (messageId) => {
    return (dispatch) => {
        dispatch({ type: GLOBAL_LOADING_START });
        dispatch({ type: startAction(DOWNLOAD_USER_NOTIFICATION_ATTACHMENT) });
        getApiInstance().notification.downloadAttachment(messageId).then(response => {
            dispatch({ type: successAction(DOWNLOAD_USER_NOTIFICATION_ATTACHMENT) });
            handleDownloadResponse(dispatch, response);
        }).catch((error) => {
            dispatch({ type: GLOBAL_LOADING_END });
            dispatch({ type: failureAction(DOWNLOAD_USER_NOTIFICATION_ATTACHMENT) });
            handleError(dispatch, {
                type: GLOBAL_ERROR_MESSAGE_ACTION,
                payload: {
                    message: error.message ? error.message : "err_msg_unknown_error",
                    className: "message_error",
                }
            }, error);
        });
    };
};