import PropTypes from "prop-types";
import React from "react";
import {ACCESS_DENIED} from "../redux/auth/actionTypes";
import {GLOBAL_ERROR_MESSAGE_ACTION, GLOBAL_MESSAGE_ACTION} from "../redux/message/actionTypes";

const REDUX_GLOBAL_RESET = "redux/global/reset";

export function createThunkMiddleware() {
    return ({dispatch, getState}) => next => action => {
        if (typeof action === "function") {
            return action(_proxiedDispatch(dispatch), getState);
        }
        return next(action);
    };
}

const timer = (typeof performance !== `undefined` && performance !== null) && typeof performance.now === `function` ? performance : Date;

function _proxiedDispatch(dispatch) {
    const _action_txid_ = timer.now();
    return action => {
        if (action.type && !action._action_txid_) {
            return dispatch({...action, _action_txid_});
        }
        return dispatch(action);
    }
}

export function createConcurrentActionHandlerMiddleware() {
    const actionRequestMap = new Map();
    return ({getState}) => (next) => (action) => {
        const actionNameFromStartAction = _resolveActionNameIfStartAction(action.type);
        if (actionNameFromStartAction && action._action_txid_) {
            const reqSessionKeySet = actionRequestMap.get(actionNameFromStartAction) || [];
            reqSessionKeySet.push(action._action_txid_);
            actionRequestMap.set(actionNameFromStartAction, reqSessionKeySet);
            return next(action);
        }
        const actionNameFromSuccessAction = _resolveActionNameIfSuccessAction(action.type);
        if (actionNameFromSuccessAction && action._action_txid_) {
            const reqSessionKeySet = actionRequestMap.get(actionNameFromSuccessAction);
            if(!reqSessionKeySet) { //说明没有startAction
                return next(action);
            } else if (reqSessionKeySet.length > 0 && action._action_txid_ === reqSessionKeySet[reqSessionKeySet.length - 1]) {
                reqSessionKeySet.length = 0;
                return next(action);
            } else {
                return;
            }
        }
        const actionNameFromFailureAction = _resolveActionNameIfFailureAction(action.type);
        if (actionNameFromFailureAction && action._action_txid_) {
            const reqSessionKeySet = actionRequestMap.get(actionNameFromFailureAction);
            if(!reqSessionKeySet) { //说明没有startAction
                return next(action);
            } else if (reqSessionKeySet.length > 0 && action._action_txid_ === reqSessionKeySet[reqSessionKeySet.length - 1]) {
                reqSessionKeySet.length = 0;
                return next(action);
            } else {
                return;
            }
        }
        return next(action);
    };
}

function _resolveActionNameIfStartAction(actionType) {
    if (actionType && typeof actionType === "string") {
        if (actionType.endsWith("/start")) {
            return actionType.substr(0, actionType.indexOf("/start"));
        } else if (actionType.endsWith("-start")) {
            return actionType.substr(0, actionType.indexOf("-start"));
        }
        return null;
    }
}

function _resolveActionNameIfSuccessAction(actionType) {
    if (actionType && typeof actionType === "string") {
        if (actionType.endsWith("/success")) {
            return actionType.substr(0, actionType.indexOf("/success"));
        } else if (actionType.endsWith("-success")) {
            return actionType.substr(0, actionType.indexOf("-success"));
        }
        return null;
    }
}

function _resolveActionNameIfFailureAction(actionType) {
    if (actionType && typeof actionType === "string") {
        if (actionType.endsWith("/failure")) {
            return actionType.substr(0, actionType.indexOf("/failure"));
        } else if (actionType.endsWith("-failure")) {
            return actionType.substr(0, actionType.indexOf("-failure"));
        }
        return null;
    }
}

/*
 *  Redux middleware to perform the state initlization fire by <code>reduxGlobalReset</code> function
 */
export function createResetMiddleware(option) {
    return (next) => (reducer, initialState) => {
        let resetType = REDUX_GLOBAL_RESET
        let resetData = "state"

        if ((typeof option === "string" && option.length > 0) || typeof option === "symbol") {
            resetType = option
        } else if (typeof option === "object") {
            resetType = typeof option.type === "string" && option.type.length > 0 || typeof option === "symbol" ? option.type : resetType
            resetData = typeof option.data === "string" && option.data.length > 0 ? option.data : resetData
        }

        const enhanceReducer = (state, action) => {
            if (action.type === resetType) {
                const needToResetState = action[resetData];
                state = {...state, ...needToResetState}
            }
            return reducer(state, action)
        }

        return next(enhanceReducer, initialState)
    }
}

/*
 *  Redux middleware to limit the state "auth.accessDenied" only change once when it is true. 
 */
export function createAccessDenyDispatchOnceMiddleware() {
    return store => next => action => {
        if (action.type === ACCESS_DENIED && store.getState().auth.accessDenied) {
            return;
        } else {
            return next(action);
        }
    }
}

/*
 *  Common redux action to reset certain state to initialized one, which will be handled by <code>resetMiddleware</code>
 */
export function reduxGlobalReset(needToResetState) {
    return (dispatch) => {
        dispatch({type: REDUX_GLOBAL_RESET, state: needToResetState});
    }
}

/*
 *  Common redux action to show error message
 */
export function reduxGlobalMessage(message) {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_MESSAGE_ACTION,
            payload: {
                message: message
            }
        });
    }
}

export function reduxGlobalErrorMessage(error) {
    return (dispatch) => {
        dispatch({
            type   : GLOBAL_ERROR_MESSAGE_ACTION,
            payload: {
                message  : (error && error.message) ? error.message : "err_msg_unknown_error",
                className: "message_error",
            }
        });
    }
}

export const ACTION_STATUS_INIT = "I";
export const ACTION_STATUS_IN_PROGRESS = "P";
export const ACTION_STATUS_DONE_SUCCESS = "S";
export const ACTION_STATUS_DONE_FAILURE = "F";

export const isActionInit = state => state === ACTION_STATUS_INIT;
export const isActionInProgress = state => state === ACTION_STATUS_IN_PROGRESS;
export const isActionSuccess = state => state === ACTION_STATUS_DONE_SUCCESS;
export const isActionFailure = state => state === ACTION_STATUS_DONE_FAILURE;

export const ActionStatusPropTypes = PropTypes.oneOf([
    ACTION_STATUS_INIT,
    ACTION_STATUS_IN_PROGRESS,
    ACTION_STATUS_DONE_SUCCESS,
    ACTION_STATUS_DONE_FAILURE
]);

export function createReducer(initialState, reducerMap) {
    return (state = initialState, action) => {
        const reducer = reducerMap[action.type];

        return reducer
            ? reducer(state, action.payload)
            : state;
    };
}

export function successAction(actionName) {
    return `${actionName}-success`;
}

export function startAction(actionName) {
    return `${actionName}-start`;
}

export function failureAction(actionName) {
    return `${actionName}-failure`;
}

export const buildStartAction = actionName => {
    return { type: startAction(actionName) };
};
export const buildSuccessAction = (actionName, payload) => {
    return { type: successAction(actionName), payload: payload ? payload : {} };
};
export const buildFailureAction = (actionName, error) => {
    return { type: failureAction(actionName), payload: error ? error : {} };
};