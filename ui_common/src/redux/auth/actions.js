import {getApiInstance} from "../../biz/api";
import {removeItem, setItem, getItem, getAndRemoveItem} from "../../utils/storageUtils";
import {STORAGE_KEY_TOKEN} from "../../utils/ssoAuthUtils";
import {getCurrentDomain} from "../../utils/appLoader";
import {removeLoggedInCookie} from "../../utils/cookieUtils";
import {
    ACCESS_DENIED,
    LOGIN_USER_FAILURE,
    LOGIN_USER_REQUEST,
    LOGIN_USER_RESET,
    LOGIN_USER_SUCCESS,
    LOGOUT_USER,
    RESET_ACCESS_DENIED,
    AUTH_FRONTEND_LOGOUT,
} from "./actionTypes";
import * as MessageActionTypes from "../message/actionTypes";
import {getI18nMsgBundle} from "../../ui/i18n";
import { getConfig } from "../../utils/configRegistry"
import {
    GLOBAL_CONFIRM_DIALOG_OPEN_ACTION,
    GLOBAL_CONFIRM_SESSION_DIALOG_OPEN_ACTION,
} from "../dialog/actionTypes";

const EXTERNAL_LOGIN = "ext_lg";
export const FRONTEND_LOGOUT_REQUIRED = "frontend_logout_required";

function setExternalLogin(isExtLogin) {
    if(isExtLogin) {
        setItem(EXTERNAL_LOGIN, isExtLogin);
    } else {
        removeItem(EXTERNAL_LOGIN);
    }
}

export function loginUserSuccess(user) {
    setExternalLogin(user.externalLogin);
    return {
        type   : LOGIN_USER_SUCCESS,
        payload: {user}
    };
}

export function loginUserFailure(error) {
    removeItem(STORAGE_KEY_TOKEN);
    return {
        type: LOGIN_USER_FAILURE
    };
}

export function loginUserRequest() {
    return {
        type: LOGIN_USER_REQUEST
    };
}

export function loginUserReset() {
    return {
        type: LOGIN_USER_RESET
    };
}

export function accessDeny(error) {
    return (dispatch) => {
        dispatch({
            type: ACCESS_DENIED,
            payload:{
                businessCode: error.businessCode,
                message: error.message
            }
        });
    }
}

export function resetAccessDeny() {
    return (dispatch) => {
        dispatch({
            type: RESET_ACCESS_DENIED
        });
    }
}

export function logout(showLogoutMessage = false) {
    return (dispatch, getState) => {
        const api = getApiInstance();
        api.auth.logout().then(response => {
            if(isExternalLogin(getState())) {
                gotoAuthLogout();
            } else {
                dispatchLogoutAndClearToken(dispatch);
                if (showLogoutMessage) {
                    setItem(FRONTEND_LOGOUT_REQUIRED, true);
                    dispatch({ type: AUTH_FRONTEND_LOGOUT });
                    dispatch({
                        type   : MessageActionTypes.GLOBAL_SUCCESS_MESSAGE_ACTION,
                        payload: {
                            message  : getI18nMsgBundle().l("message_logout_success"),
                            className: "message_normal",
                        }
                    });
                }
            }
        }).catch(error => {
            if(isExternalLogin(getState)) {
                gotoAuthLogout();
            } else {
                dispatchLogoutAndClearToken(dispatch);
            }
        });
    };
}

export function requireAuthFrountendLogout() {
    return getAndRemoveItem(FRONTEND_LOGOUT_REQUIRED);
}

function isExternalLogin(state) {
    return (state && state.auth && state.auth.user && state.auth.user.externalLogin) || getItem(EXTERNAL_LOGIN);
}

function gotoAuthLogout() {
    clearToken();
    var url = `${getConfig().authServerUrl}/logout`;
    const domain = getCurrentDomain(getConfig());
    if(domain != null) {
        url = `${url}?market=${domain}`;
    }
    window.location.replace(url);
}

function clearToken() {
    removeItem(STORAGE_KEY_TOKEN);
    removeLoggedInCookie();
}

function dispatchLogoutAndClearToken(dispatch) {
    clearToken();
    dispatch({type: LOGOUT_USER});
}

// 登录流程，portal页面登录特殊-刷新页面。
export function exportPingOutTimeLoginOut(){
    const webFrontendLogoutRequired = getItem("webFrontendLogoutRequired");
    return (dispatch, getState) => {
        //忽略返回token error失效的其他情况，这里是为了确保后台destroyToken
        const api = getApiInstance();
        api.auth.logout().then(response => {
            doLogoutProcess(dispatch, getState, webFrontendLogoutRequired);
        }).catch(error => {
            doLogoutProcess(dispatch, getState, webFrontendLogoutRequired);
        })
    }
}

export function doLogoutProcess(dispatch, getState, webFrontendLogoutRequired) {
    if(isExternalLogin(getState)) {
        gotoAuthLogout();
    } else {
        dispatchLogoutAndClearToken(dispatch);
        if (webFrontendLogoutRequired){
            window.location.reload();
        }
    }
}

export function authTokenDialog(callback) {

    // 取消定时器，让页面不刷新。显示弹层。在弹层中点击页面。方才跳转。
    // 点击后执行登出。

    clearInterval(global.fetchMsgTimer);
    clearInterval(global.timer);

    const callbacks = ()=>{
        callback && callback();
    };
    return (dispatch, getState) => {
        dispatch({
            type   : GLOBAL_CONFIRM_SESSION_DIALOG_OPEN_ACTION,
            payload: {
                message    : "message",
                messageDesc: "messageDesc",
                callback   : callbacks,
            }
        })
    }
}
