import {getAndRemoveItem, getItem, removeItem, setItem} from "./storageUtils";
import isNil from "lodash/isNil";
import queryString from "querystring";
import {getApiInstance, getSsoApiInstance} from "../biz/api";
import {OAuthGetTokenByCodeFailureError, OAuthStateMismatchError, SsoLoginTriedTimesExceedError} from "../error";
import {getCurrentDomain, isPaxStoreMainHostAccess} from "./appLoader";
import {getCurrentLocale} from "./cookieUtils";

const ssoStateKey = "sso_state";
export const STORAGE_KEY_TOKEN = "token";
const savedURLKey = "saved_url";
export const STORAGE_KEY_CODE_CHALLENGE = "code_challenge";
const MAX_LOGIN_TRIED_TIEMS = 3;
const STORAGE_KEY_LOGIN_TRIED_TIMES = "lg_tried_times";

export function generateRendomKey(keySize = 32) {
    const _chars = "ABCDEFGHJKLMNOPQRSTWXYZabcdefhijklmnoprstwxyz1234567890-._~";
    const maxPos = _chars.length;
    let result = "", i = 0;
    for (; i < keySize; i++) {
        result += _chars.charAt(Math.floor(Math.random() * maxPos));
    }
    return result;
}

export function keepSavedURL(savedURL) {
    setItem(savedURLKey, savedURL);
}

export function processSavedURL() {
    const savedUrl = getAndRemoveItem(savedURLKey);
    if (!isNil(savedUrl)) window.location.hash = savedUrl;
}

export function getSsoLoginURL({authServerURL, clientId, market, locale, redirectUri}) {

    let tmpLocale = locale;
    if (isNil(tmpLocale)) {
        tmpLocale = "zh_CN";
    }
    const generatedState = generateRendomKey();
    const codeChallenge = generateRendomKey(43);
    setItem(ssoStateKey, generatedState);
    setItem(STORAGE_KEY_CODE_CHALLENGE, codeChallenge);

    const SHA256 = require("crypto-js/sha256");
    const BASE64 = require("crypto-js/enc-base64");

    const hashedCodeChallengeArray = SHA256(codeChallenge);
    const base64HashStr = hashedCodeChallengeArray.toString(BASE64);

    const param = {
        response_type : "code",
        client_id     : clientId,
        scope         : "openid",
        state         : encodeURIComponent(generatedState),
        locale        : tmpLocale,
        code_challenge: encodeURIComponent(base64HashStr)
        //code_challenge_method: "S256"
    };

    if (!isNil(redirectUri)) {
        param.redirect_uri = redirectUri
    }

    if (!isNil(market)) {
        param["market"] = market;
    }
    return `${authServerURL}/oauth/authorize?${queryString.stringify(param)}`;
}

function resolveCurrentHash() {
    let currnetHash = window.location.hash;
    if (isNil(currnetHash)) currnetHash = location.hash;

    let result = {};
    if (currnetHash) {
        if (currnetHash.startsWith("#")) {
            currnetHash = currnetHash.slice(1);
        }
        const regex = /([^&=]+)=([^&]*)/g;
        let m;
        while ((m = regex.exec(currnetHash)) !== null) {
            result[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
        }
    }
    return result;
}

function invokeCurrentTokenApi(options, i18nTools, userLoginAction, successCallback, failureCallback) {
    return getApiInstance().auth.current(options.config.clientId).then(userInfo => {
        userLoginAction(userInfo);//user login action is asynchronous call
        return userInfo;
    }).then(userInfo => {
        successCallback(options, i18nTools, userInfo);//successCallback have to be called after login action is done
    }).catch(e => {
        failureCallback(options, i18nTools, e);
    });
}

function purgeCurrentURL() {
    if (window.history.pushState) {
        window.history.pushState("", document.title, window.location.pathname);
    } else {
        window.location.hash = "";
    }
}

export function resolveCurrentAuthzCode(options, i18nTools, userLoginAction, successCallback, failureCallback) {
    let token = getItem(STORAGE_KEY_TOKEN);
    if (!isNil(token)) {
        //call login user success action if token is in session storage already
        return invokeCurrentTokenApi(options, i18nTools, userLoginAction, successCallback, failureCallback);
    }

    const queryStrObj = resolveCurrentHash();
    if (queryStrObj) {
        const keys = Object.keys(queryStrObj) || [];
        if (keys.indexOf("state") >= 0 && keys.indexOf("authz_code") >= 0) {
            purgeCurrentURL();
            const state = queryStrObj["state"];
            const storedState = getAndRemoveItem(ssoStateKey);
            const storedCodeChallenge = getAndRemoveItem(STORAGE_KEY_CODE_CHALLENGE);

            if (!isNil(state) && state !== storedState) {
                countLoginTimes();
                throw new OAuthStateMismatchError();
            }

            const tokenForm = new FormData();
            tokenForm.append("code", queryStrObj["authz_code"]);
            tokenForm.append("grant_type", "authorization_code");
            tokenForm.append("scope", "openid");
            tokenForm.append("client_id", options.config.clientId);
            tokenForm.append("code_verifier", storedCodeChallenge);

            const redirectUri = resolveRedirectUrl(options.config);
            if (!isNil(redirectUri)) {
                tokenForm.append("redirect_uri", redirectUri);
            }

            return getSsoApiInstance().postCodeForToken(tokenForm).then(response => {
                removeItem(STORAGE_KEY_LOGIN_TRIED_TIMES);
                //save token to session storage
                setItem(STORAGE_KEY_TOKEN, response.access_token);
                //call login user success action
                invokeCurrentTokenApi(options, i18nTools, userLoginAction, successCallback, failureCallback);
            }).catch(e => {
                countLoginTimes();
                throw new OAuthGetTokenByCodeFailureError();
            });
        }
    }
    return null;
}

function countLoginTimes() {
    let lgTried = getItem(STORAGE_KEY_LOGIN_TRIED_TIMES);
    if (isNil(lgTried)) lgTried = 0;
    lgTried = Number(lgTried) + 1;
    if (lgTried < MAX_LOGIN_TRIED_TIEMS) {
        setItem(STORAGE_KEY_LOGIN_TRIED_TIMES, lgTried);
    } else {
        removeItem(STORAGE_KEY_LOGIN_TRIED_TIMES);
        throw new SsoLoginTriedTimesExceedError();
    }
}

export function redirectToLogin(authServerURL, clientId, market, locale) {
    const url = getSsoLoginURL({authServerURL, clientId, market, locale});
    window.location.replace(url);
}

export function redirectToLogin2(config) {
    const redirectUri = resolveRedirectUrl(config);
    const authServerURL = config.authServerUrl;
    const clientId = config.clientId;
    const market = getCurrentDomain(config);
    const locale = getCurrentLocale();
    const url = getSsoLoginURL({authServerURL, clientId, market, locale, redirectUri});
    window.location.replace(url);

}

const resolveRedirectUrl = config => {
    let result = null;
    if (!isPaxStoreMainHostAccess(config)) {
        const hostname = window.location.host;
        if (hostname.indexOf(":") > 0) {
            //maybe in dev
            result = `${window.location.protocol}//${window.location.host}`;
        } else {
            result = `${window.location.protocol}//${window.location.host}/${config.clientId}/`;
        }
    } else if (config.env == "dev") {
        result = `${window.location.protocol}//${window.location.host}`;
    }
    return result;
}
