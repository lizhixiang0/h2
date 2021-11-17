import isNil from "lodash/isNil";
import isArray from "lodash/isArray";
import split from "lodash/split";
import {isPaxStoreMainHostAccess} from "./appLoader";
import { useQueries, createHashHistory} from "history";
import qs from "qs";

export function isValidRoute(routes, name) {

    if (isNil(routes) || !isArray(routes) || isNil(name)) return false;

    let tmpRoute;
    for (let i = 0; i < routes.length; i++) {
        tmpRoute = routes[i];
        if (tmpRoute.name && "/" + tmpRoute.name === name) {
            return true;
        } else if (tmpRoute.childRoutes && tmpRoute.childRoutes.length > 0) {
            if (isValidRoute(tmpRoute.childRoutes, name)) return true;
        }
    }
    return false;
}

/**
 * Handle the onEnter event for PageNotFound Route.
 * as currently after SSO login,
 * click browser"s back button will cause the URL in location bar with "/access_token=xxx" and PageNotFound will display.
 *
 * @export
 * @param {any} pathname From react-router"s onEnter callback function
 * @param {any} replace From react-router"s onEnter callback function
 * @param {any} url URL will be replace if matched
 */
export function handleEnterForPageNotFoundRoute(pathname, replace, url) {
    // if(pathname && pathname.indexOf("access_token=") >= 0) replace(url);
    if (pathname && pathname.indexOf("authz_code=") >= 0 && pathname.indexOf("state=") >= 0) replace(url);
}

function makeMarketHostURL(contextPath) {
    const hostname = window.location.host;
    const protocol = window.location.protocol;
    if (hostname.indexOf(":") > 0) {
        return `${protocol}//${hostname}`;
    } else {
        return `${protocol}//${hostname}/${contextPath}`;
    }
}

export function resolveBaseURL(config, forcePaxMainHostAccess = false) {
    return config.baseUrl;
}

export function resolveAccountURL(config, forcePaxMainHostAccess = false) {
    if (forcePaxMainHostAccess || isPaxStoreMainHostAccess(config)) {
        return config.moduleUrls.account;
    } else {
        return makeMarketHostURL(config.moduleContextPath.account);
    }
}

export function resolveAdminURL(config, domain, forcePaxMainHostAccess = false) {
    if (forcePaxMainHostAccess || isPaxStoreMainHostAccess(config)) {
        return config.moduleUrls.admin.replace("{domain}", domain);
    } else {
        return makeMarketHostURL(config.moduleContextPath.admin);
    }
}

export function resolvePortalURL(config, domain, forcePaxMainHostAccess = false) {
    if (forcePaxMainHostAccess || isPaxStoreMainHostAccess(config)) {
        return config.moduleUrls.portal.replace("{domain}", domain);
    } else {
        return makeMarketHostURL(config.moduleContextPath.portal);
    }
}
export function resolveMerchantURL(config, domain, forcePaxMainHostAccess = false) {
    if (forcePaxMainHostAccess || isPaxStoreMainHostAccess(config)) {
        return config.moduleUrls.merchant.replace("{domain}", domain);
    } else {
        return makeMarketHostURL(config.moduleContextPath.merchant);
    }
}

export function resolveDeveloperURL(config, domain, forcePaxMainHostAccess = false) {
    if (forcePaxMainHostAccess || isPaxStoreMainHostAccess(config)) {
        return config.moduleUrls.developer.replace("{domain}", domain);
    } else {
        return makeMarketHostURL(config.moduleContextPath.developer);
    }
}

export function resolveSuperURL(config, forcePaxMainHostAccess = false) {
    if (forcePaxMainHostAccess || isPaxStoreMainHostAccess(config)) {
        return config.moduleUrls.super;
    } else {
        return makeMarketHostURL(config.moduleContextPath.super);
    }
}

export function resolveDeveloperGuideURL(envCode, systemVersion, baseUrl, secondUrl) {
    return resolveDocCenterURL(envCode, systemVersion, baseUrl, secondUrl, "develop");
}

export function resolveAdminGuideURL(envCode, systemVersion, baseUrl, secondUrl) {
    return resolveDocCenterURL(envCode, systemVersion, baseUrl, secondUrl, "admin");
}

export const resolveDocCenterURL = (envCode, systemVersion, baseUrl, secondUrl, clientId) => {
    // 判断是否是文档中心的链接， 否者直接跳转baseUrl
    if(!isPaxstoreDocCenter(baseUrl)) {
        return baseUrl;
    }
    let verSplit = split(systemVersion, "_");
    let ver = verSplit.length > 0? verSplit[0] : "";
    if(secondUrl){
        if(!secondUrl.startsWith("/")){
            secondUrl = "/" + secondUrl;
        }
    }else{
        secondUrl="/home";
    }
    const hostname = window.location.hostname;
    let market = hostname.substring(0, hostname.indexOf("."));
    if(secondUrl.indexOf("?") < 0) {
        // 不存在参数
        return `${baseUrl}${secondUrl}?origin=${clientId}&market=${market}&env=${envCode}&version=${ver}`;
    } else {
        return `${baseUrl}${secondUrl}&origin=${clientId}&market=${market}&env=${envCode}&version=${ver}`;
    }

};

function isPaxstoreDocCenter(url) {
    return url && (url.indexOf("docs.sit.whatspos.cn") > 0 || url.indexOf("docs.whatspos.com") > 0);
}

export const base64HashHistory =  useQueries(createHashHistory)({
    parseQueryString: (queryString) => {
        let objStr = "";
        try {
            objStr = atob(queryString);
        } catch (e) {
            objStr = queryString;
        }
        return qs.parse(objStr,  { parseArrays: false });
    },
    stringifyQuery: (query) => {
        return btoa(qs.stringify(query,{ arrayFormat: "indices" }));
    }
});
