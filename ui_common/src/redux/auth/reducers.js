import {createReducer} from "../../utils";
import {getItem} from "../../utils/storageUtils";
import {STORAGE_KEY_TOKEN} from "../../utils/ssoAuthUtils";
import {
    ACCESS_DENIED,
    LOGIN_USER_FAILURE,
    LOGIN_USER_REQUEST,
    LOGIN_USER_RESET,
    LOGIN_USER_SUCCESS,
    LOGOUT_USER,
    RESET_ACCESS_DENIED,
    AUTH_FRONTEND_LOGOUT
} from "./actionTypes";
import initialAuthState from "./initState";

export const auth = createReducer(initialAuthState, {
    [LOGIN_USER_REQUEST]: state => {
        return {
            ...state,
            isAuthenticating: true
        };
    },

    [LOGIN_USER_SUCCESS]: (state, payload) => {
        return {
            ...state,
            isAuthenticating: false,
            isAuthenticated : true,
            token           : getItem(STORAGE_KEY_TOKEN),
            user            : payload.user
        };

    },

    [LOGIN_USER_FAILURE]: state => {
        return {
            ...state,
            isAuthenticating: false,
            isAuthenticated : false,
            token           : null,
            user            : null
        };
    },

    [LOGIN_USER_RESET]: (state, payload) => {
        return initialAuthState;
    },

    [LOGOUT_USER]        : state => {
        return {
            ...state,
            isAuthenticated: false,
            isLogout       : true,
            isAuthFrontendLogout: false,
            token          : null,
            user           : null
        };
    },
    [ACCESS_DENIED]      : (state,payload) => {
        return {
            ...state,
            accessDenied: true,
            businessCode: payload.businessCode,
            message     : payload.message
        };
    },
    [RESET_ACCESS_DENIED]: state => {
        return {
            ...state,
            accessDenied: false
        };
    },
    [AUTH_FRONTEND_LOGOUT]: state => {
        console.log(`>>>>>>>>> AUTH_FRONTEND_LOGOUT: state=${state}`);
        return {
            ...state,
            isAuthFrontendLogout: true
        };
    }
});