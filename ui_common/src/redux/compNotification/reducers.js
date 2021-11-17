import {
    ACTION_STATUS_DONE_FAILURE,
    ACTION_STATUS_DONE_SUCCESS,
    ACTION_STATUS_IN_PROGRESS,
    ACTION_STATUS_INIT,
    createReducer,
    startAction,
    successAction,
    failureAction
} from "../../utils";
import * as ActionTypes from "./actions";

export const fetchUserNotificationMsgStatsInitState = {
    actionStatus: ACTION_STATUS_INIT,
    viewMessageActionStatus: ACTION_STATUS_INIT,
    readMessageActionStatus: ACTION_STATUS_INIT,
    readTopXMessageActionStatus: ACTION_STATUS_INIT,
    downloadAttachmentActionStatus: ACTION_STATUS_INIT,
    resetRefreshIntervalActionStatus: ACTION_STATUS_INIT,
    stats: undefined,
    msgItem: undefined
};

export const fetchUserNotificationMsgStatsReducer = createReducer(fetchUserNotificationMsgStatsInitState, {
    [startAction(ActionTypes.RESET_USER_NOTIFICATION_REFRESH_INTERVAL)]: state => {
        return {
            ...state,
            resetRefreshIntervalActionStatus: ACTION_STATUS_IN_PROGRESS
        }
    },
    [successAction(ActionTypes.RESET_USER_NOTIFICATION_REFRESH_INTERVAL)]: (state, payload) => {
        return {
            ...state,
            resetRefreshIntervalActionStatus: ACTION_STATUS_DONE_SUCCESS,
            ...payload,
            error: null
        }
    },

    [startAction(ActionTypes.FETCH_USER_NOTIFICATION_MSG_STATS)]: state => {
        return {
            ...state,
            stats: undefined,
            actionStatus: ACTION_STATUS_IN_PROGRESS
        }
    },
    [successAction(ActionTypes.FETCH_USER_NOTIFICATION_MSG_STATS)]: (state, payload) => {
        return {
            ...state,
            actionStatus: ACTION_STATUS_DONE_SUCCESS,
            ...payload,
            error: null
        }
    },
    [failureAction(ActionTypes.FETCH_USER_NOTIFICATION_MSG_STATS)]: (state, payload) => {
        return {
            ...state,
            actionStatus: ACTION_STATUS_DONE_FAILURE,
            error: payload.error
        }
    },

    [startAction(ActionTypes.VIEW_USER_NOTIFICATION_MESSAGE)]: state => {
        return { ...state, msgItem: undefined, viewMessageActionStatus: ACTION_STATUS_IN_PROGRESS }
    },
    [successAction(ActionTypes.VIEW_USER_NOTIFICATION_MESSAGE)]: (state, payload) => {
        return {
            ...state,
            viewMessageActionStatus: ACTION_STATUS_DONE_SUCCESS,
            msgItem: payload.response,
            error: null
        }
    },
    [failureAction(ActionTypes.VIEW_USER_NOTIFICATION_MESSAGE)]: (state, payload) => {
        return {
            ...state,
            viewMessageActionStatus: ACTION_STATUS_DONE_FAILURE,
            error: payload.error
        }
    },

    [ActionTypes.CLEAR_USER_NOTIFICATION_MESSAGE]: state => {
        return {
            ...state,
            viewMessageActionStatus: ACTION_STATUS_INIT,
            msgItem: undefined,
            error: null
        }
    },

    [startAction(ActionTypes.READ_USER_NOTIFICATION_MESSAGE)]: state => {
        return { ...state, msgItem: undefined, readMessageActionStatus: ACTION_STATUS_IN_PROGRESS }
    },
    [successAction(ActionTypes.READ_USER_NOTIFICATION_MESSAGE)]: (state, payload) => {
        return {
            ...state,
            readMessageActionStatus: ACTION_STATUS_DONE_SUCCESS,
            ...payload,
            error: null
        }
    },
    [failureAction(ActionTypes.READ_USER_NOTIFICATION_MESSAGE)]: (state, payload) => {
        return {
            ...state,
            readMessageActionStatus: ACTION_STATUS_DONE_FAILURE,
            error: payload.error
        }
    },

    [startAction(ActionTypes.READ_USER_NOTIFICATION_TOPX_MESSAGES)]: state => {
        return { ...state, msgItem: undefined, readTopXMessageActionStatus: ACTION_STATUS_IN_PROGRESS }
    },
    [successAction(ActionTypes.READ_USER_NOTIFICATION_TOPX_MESSAGES)]: (state, payload) => {
        return {
            ...state,
            readTopXMessageActionStatus: ACTION_STATUS_DONE_SUCCESS,
            ...payload,
            error: null
        }
    },
    [failureAction(ActionTypes.READ_USER_NOTIFICATION_TOPX_MESSAGES)]: (state, payload) => {
        return {
            ...state,
            readTopXMessageActionStatus: ACTION_STATUS_DONE_FAILURE,
            error: payload.error
        }
    },

    [startAction(ActionTypes.DOWNLOAD_USER_NOTIFICATION_ATTACHMENT)]: state => {
        return {
            ...state,
            downloadAttachmentActionStatus: ACTION_STATUS_IN_PROGRESS
        }
    },
    [successAction(ActionTypes.DOWNLOAD_USER_NOTIFICATION_ATTACHMENT)]: (state) => {
        return {
            ...state,
            downloadAttachmentActionStatus: ACTION_STATUS_DONE_SUCCESS
        }
    },
    [failureAction(ActionTypes.DOWNLOAD_USER_NOTIFICATION_ATTACHMENT)]: (state) => {
        return {
            ...state,
            downloadAttachmentActionStatus: ACTION_STATUS_DONE_FAILURE
        }
    }
});
