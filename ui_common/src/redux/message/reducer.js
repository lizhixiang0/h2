import {createReducer} from "../../utils";
import {messageInitState} from "./initState";
import {
    GLOBAL_ERROR_MESSAGE_ACTION,
    GLOBAL_INFO_MESSAGE_ACTION,
    GLOBAL_MESSAGE_ACTION,
    GLOBAL_SUCCESS_MESSAGE_ACTION,
    GLOBAL_WARNING_MESSAGE_ACTION
} from "./actionTypes";

export const messageReducer = createReducer(messageInitState, {
    [GLOBAL_MESSAGE_ACTION]        : (state, payload) => {
        return {
            ...state,
            message  : payload.message,
            style    : payload.style,
            bodyStyle: payload.bodyStyle,
            className: payload.className,
            autoHide : !payload.autoHide === false,
            callback : payload.callback || undefined,
        }
    },
    [GLOBAL_INFO_MESSAGE_ACTION]   : (state, payload) => {
        return {
            ...state,
            message  : payload.message,
            style    : {...payload.style, backgroundColor: "#5b5f87"},
            bodyStyle: payload.bodyStyle,
            className: payload.className,
            autoHide : !payload.autoHide === false,
            callback : payload.callback || undefined,
        }
    },
    [GLOBAL_ERROR_MESSAGE_ACTION]  : (state, payload) => {
        return {
            ...state,
            message  : payload.message,
            style    : {...payload.style, backgroundColor: "#ef4f30"},
            bodyStyle: payload.bodyStyle,
            className: payload.className,
            existShowMsg:payload.existShowMsg,
            errtype:true,
            existMsgs:payload.existMsgs,
            autoHide : !payload.autoHide === false,
            callback : payload.callback || undefined,
        }
    },
    [GLOBAL_WARNING_MESSAGE_ACTION]: (state, payload) => {
        return {
            ...state,
            message  : payload.message,
            style    : {...payload.style, backgroundColor: "#ff9800"},
            bodyStyle: payload.bodyStyle,
            className: payload.className,
            autoHide : !payload.autoHide === false,
            callback : payload.callback || undefined,
        }
    }
    ,
    [GLOBAL_SUCCESS_MESSAGE_ACTION]: (state, payload) => {
        return {
            ...state,
            message  : payload.message,
            style    : {...payload.style, backgroundColor: "#63af57"},
            bodyStyle: payload.bodyStyle,
            className: payload.className,
            existShowMsg:payload.existShowMsg,
            existMsgs:payload.existMsgs,
            autoHide : payload.existShowMsg?false:true,
            callback : payload.callback || undefined,
        }
    }
})