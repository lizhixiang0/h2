
export {
    //redux middleware
    createResetMiddleware,
    createAccessDenyDispatchOnceMiddleware,
    createThunkMiddleware,
    createConcurrentActionHandlerMiddleware,

    //common redux action
    reduxGlobalReset,
    reduxGlobalMessage,
    reduxGlobalErrorMessage,

    ACTION_STATUS_INIT,
    ACTION_STATUS_IN_PROGRESS,
    ACTION_STATUS_DONE_SUCCESS,
    ACTION_STATUS_DONE_FAILURE,

    isActionInit,
    isActionInProgress,
    isActionSuccess,
    isActionFailure,
    createReducer,

    ActionStatusPropTypes,

    startAction,
    successAction,
    failureAction,
    buildStartAction,
    buildFailureAction,
    buildSuccessAction
} from "./reduxUtils";

export {
    getCurrentLocale,
    setLocaleCookie,
    getCurrentListShape,
    setListShape,
    isAllowCatAccCookies,
    allowCatAccCookies,
    setCookie,
    getCookieValue,
    setLoggedInCookie,
    removeLoggedInCookie,
    isLoggedInCookieSet,
    setResellerCookie,
    getCurrentReseller,
    getCurrentMerchantCookie,
    setMerchantCookie,
} from "./cookieUtils";

export {getMinSdkVersionDesc, getApkModelValues, getApkPaxPermissionValues, getApkPermissionValues, getAppResellerValues, getApkViewInfo, getCategoryValues} from "./apkUtils";

export {
    dateToString,
    getMonthDesc,
    humanFormatBetweenDates,
    humanFormatSeconds,
    getTimezone,
    getTimezoneOffset,
    getBriefDate,
    getTimetamp,
    getUtcOffset,
    getDatePickerDay,
    getDatePickerWeek,
    getDatePickerDays,
    getDatePickerMonth,
} from "./dateUtils";

export {
    getMaskString,
    isEmail,
    isPasswordValid,
    isURLValid,
    isIPAddressValid,
    isPortValid,
    trimObjectProps,
    getShortString,
    getShortBackString,
    getQueryString,
    getObjectProps,
    formatDangerousMessage,
    getBytesCount,
    isNotBlank,
    isJsonValue,
    capitalWord,
    getSymbolReplace,
} from "./stringUtils";

export {
    blobToFile,
    getBase64Image,
    getFileByBase64,
    getBase64ByImgUrl
} from "./fileUtils";

export {
    setItem,
    removeItem,
    getItem,
    getAndRemoveItem,
    setLocalItem,
    getLocalItem,
    removeLocalItem,
    getAndRemoveLocalItem,
    setOrderLocalItem
} from "./storageUtils";

export {
    getSsoLoginURL,
    resolveCurrentAuthzCode,
    redirectToLogin,
    redirectToLogin2,
    STORAGE_KEY_TOKEN,
    STORAGE_KEY_CODE_CHALLENGE,
    keepSavedURL,
    processSavedURL,
    generateRendomKey
} from "./ssoAuthUtils";

export {
    isValidRoute,
    handleEnterForPageNotFoundRoute,
    resolveAccountURL,
    resolveAdminURL,
    resolveDeveloperURL,
    resolvePortalURL,
    resolveMerchantURL,
    resolveSuperURL,
    resolveBaseURL,
    resolveAdminGuideURL,
    resolveDeveloperGuideURL,
    base64HashHistory
} from "./routerUtils";

export {
    isPaxStoreMainHostAccess
} from "./appLoader";

import {getCurrentDomain} from "./appLoader";

export const getDomain = (config) => {
    return getCurrentDomain(config);
}

export {
    getMarkByCurrencyCode,
    formatMoney,
    formatPercentage
} from "./currencyUtils";

export {
    isPrivilegeAllowed
} from "./privilegeUtils";

export {
    getDisplayFileSize,
    convertSizeMBToB
} from "./sizeUtils"

export {
    getConfig,
    registerConfig
} from "./configRegistry"

export {
    encryptPassword,
    encryptParameter,
    isEncryptedParameter,
    maskParameter
} from "./cryptoUtils"

export {
    setBuriedPoint,
    clearBuriedPoint
} from "./buriedPointUtils"

export {
    getClientInfoFromBrowser
} from "./browserUtils"

export {
    range,
    disabledDate,
    disabledDateTime,
    notIsOncedisabledDateTime,
    disabledRangeTime,
    disabledTimeExpire
} from "./disabledTimeUtils"

export {
    getVasServiceByType,
    findVasServicesExcluded,
    isVasServiceEnabled
} from "./marketUtils"