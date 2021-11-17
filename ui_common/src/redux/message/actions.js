import {GLOBAL_MESSAGE_ACTION} from "./actionTypes";
import {resetUserNotificationRefreshInterval} from "../compNotification";
import Color from "../../styles/Color";

export const sendGlobalMessage = (message, messageConfig) => {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_MESSAGE_ACTION,
            payload: {
                message: message,
                style  : {
                    backgroundColor: Color.primaryColor
                },
                ...messageConfig,
            }
        })
    }

}

export const sendGlobalWarningMessage = (message, messageConfig) => {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_MESSAGE_ACTION,
            payload: {
                message: message,
                style  : {
                    backgroundColor: Color.orange
                },
                ...messageConfig,
            }
        })
    }
}

export const sendGlobalInfoMessage = (message, messageConfig) => {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_MESSAGE_ACTION,
            payload: {
                message: message,
                style  : {
                    backgroundColor: Color.secondaryPurple
                },
                ...messageConfig,
            }
        })
    }
}

export const sendGlobalSuccessMessage = (message, messageConfig) => {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_MESSAGE_ACTION,
            payload: {
                message : message,
                style   : {
                    backgroundColor: Color.green
                },
                autoHide: true,
                ...messageConfig,

            }
        })
    }
}

export const sendGlobalErrorMessage = (message, messageConfig) => {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_MESSAGE_ACTION,
            payload: {
                message: message,
                style  : {
                    backgroundColor: Color.red
                },
                ...messageConfig,
            }
        })
    }
}

export const sendImportResponseMessage = (response) => {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_MESSAGE_ACTION,
            payload: {
                message: response.message,
                style  : {
                    backgroundColor: response.businessCode == 0 ? Color.primaryColor : Color.secondaryPurple,
                },
            }
        });
        if(response.businessCode != 0) {
            resetUserNotificationRefreshInterval(10, 3)(dispatch);
        }
    }
}