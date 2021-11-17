import cookie from "cookie";

const LOCALE_COOKIE_KEY = "locale";
const RESELLER_COOKIE_KEY = "reseller";
const MERCHANT_COOKIE_KEY = "merchant";
const LOGGED_IN_COOKIE_KEY = "_p_logged_in_";
const LIST_SHAPE_COOKIE_KEY = "_list_shape_";
const CAT_ACC_COOKIE_KEY = "catAccCookies";

export function getCurrentLocale() {
    const curLocale = getCookieValue(LOCALE_COOKIE_KEY);
    if (curLocale && curLocale.indexOf("-") >= 0) {
        setCookie(LOCALE_COOKIE_KEY, "", "/", 0);
        return undefined;
    }
    return curLocale;
}

export function setLocaleCookie(locale, path = "/") {
    setCookie(LOCALE_COOKIE_KEY, locale, path, 365 * 24 * 60 * 60);
}

export function getCurrentListShape() {
    const curListShape = getCookieValue(LIST_SHAPE_COOKIE_KEY);
    if (curListShape && curListShape.indexOf("-") >= 0) {
        setCookie(LIST_SHAPE_COOKIE_KEY, "", "/", 0);
        return undefined;
    }
    return curListShape;
}

export function setListShape(listShape, path = "/") {
    setCookie(LIST_SHAPE_COOKIE_KEY, listShape, path, 365 * 24 * 60 * 60);
}

export function isAllowCatAccCookies() {
    const isAllow = getCookieValue(CAT_ACC_COOKIE_KEY);
    return isAllow && isAllow > 0;
}

export function allowCatAccCookies(isAllow, path = "/") {
    setCookie(CAT_ACC_COOKIE_KEY, isAllow, path, 30 * 24 * 60 * 60);
}

export function getCurrentReseller() {
    return getCookieValue(RESELLER_COOKIE_KEY);
}

export function setResellerCookie(reseller, path = "/") {
    setCookie(RESELLER_COOKIE_KEY, reseller, path, 365 * 24 * 60 * 60);
}
export function getCurrentMerchantCookie() {
    return getCookieValue(MERCHANT_COOKIE_KEY);
}

export function setMerchantCookie(reseller, path = "/") {
    setCookie(MERCHANT_COOKIE_KEY, reseller, path, 365 * 24 * 60 * 60);
}

export function setCookie(key, value, path, maxAge) {
    const options = {path};

    if (maxAge >= 0) {
        options["maxAge"] = maxAge;
        const date = new Date();
        date.setTime(date.getTime() + (maxAge * 1000));
        options["expires"] = date;
    }

    const domain = resolveDomain();
    if (domain != null) {
        options["domain"] = domain;
    }

    document.cookie = cookie.serialize(key, value, options);
}

function resolveDomain() {
    const hostname = window.location.hostname;
    if (hostname === "localhost" || hostname === "127.0.0.1") return hostname;
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    const domain = parts.slice(1).join(".");
    if (domain.indexOf("whatspos.cn") > 0) return "whatspos.cn";
    if (domain.indexOf("whatspos.com") > 0) return "whatspos.com";
    if (domain.indexOf("paxszapp.com") > 0) return "paxszapp.com";
    return domain
}

export function getCookieValue(key) {
    return cookie.parse(document.cookie)[key];
}

export function setLoggedInCookie() {
    setCookie(LOGGED_IN_COOKIE_KEY, "true", "/", -1);
}

export function removeLoggedInCookie() {
    setCookie(LOGGED_IN_COOKIE_KEY, "", "/", 0);
}

export function isLoggedInCookieSet() {
    return "true" === getCookieValue(LOGGED_IN_COOKIE_KEY);
}