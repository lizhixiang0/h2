import React from "react";
import ReactDOM from "react-dom";
import {Provider} from "react-redux";
import fetch from "isomorphic-fetch";
import isBoolean from "lodash/isBoolean";
import isNil from "lodash/isNil";
import isFunction from "lodash/isFunction";
import MuiThemeProvider from "material-ui/styles/MuiThemeProvider";
import {LoginFailedErrorView, UnsupportedBrowserError} from "../ui/error";
import {HttpFetchFailedError, isNetworkError, SsoLoginTriedTimesExceedError} from "../error";
import {getApiInstance, getSsoApiInstance, setApiInstance} from "../biz/api";
import {loginUserSuccess} from "../redux/auth/actions";
import * as CookieUtils from "./cookieUtils";
import * as StorageUtils from "./storageUtils";
import * as BrowserUtils from "./browserUtils";
import {initPasswordEncrypt} from "./cryptoUtils";
import {processSavedURL, redirectToLogin2, resolveCurrentAuthzCode, STORAGE_KEY_TOKEN} from "./ssoAuthUtils";
import {I18nProvider, I18nTools, UserProvider} from "../ui";

const renderError = (options, i18nTools, error) => {
    ReactDOM.render(
        <MuiThemeProvider muiTheme={options.muiTheme}>
            <LoginFailedErrorView
                i18nTools={i18nTools}
                contextPath={options.config.contextPath}
                config={options.config}
                error={error}
            />
        </MuiThemeProvider>, options.container
    );
    changeTitleAndFavicon(options, i18nTools);
}

const initMarket = (options) => {
    if (!getApiInstance().auth) {
        throw new Error("AuthApi is not initialized");
    }
    return getApiInstance().auth.getMarket(options.activeMarketOnly, options.config.clientId).then(data => {
        options.store.dispatch(options.loadMarketSuccessAction(data));
        initPasswordEncrypt(data);
    });
}

const initMarketDc = (options) => {
    if (!getApiInstance().auth) {
        throw new Error("AuthApi is not initialized");
    }
    if (!options.prepareApi) {
        throw new Error("prepareApi is not initialized");
    }
    return getApiInstance().auth.getMarketDc(getCurrentDomain(options.config)).then(dcData => {
        setApiInstance(options.prepareApi(dcData.dcUrl))
    });
}

const initI18n = (options) => {
    const {config} = options;
    let locale = CookieUtils.getCurrentLocale();
    if (!locale) {
        locale = BrowserUtils.getBrowserLocale(config);
        CookieUtils.setLocaleCookie(locale);
    }

    const resourceVersion = window.__RESOURCE_VERSION__ || "";
    return fetch(`${config.contextPath}assets/lang/${locale}${resourceVersion}.json`).then(res => {
        if (!res.ok) {
            return Promise.reject(new HttpFetchFailedError(res.status, res.statusText));
        }
        return res.json();
    }).then(localeData => {
        return new I18nTools({localeData, locale});
    }, failureRes => {
        return fetch(`${config.contextPath}assets/lang/en${resourceVersion}.json`).then((enRes) => {
            if (!enRes.ok) {
                return Promise.reject(new HttpFetchFailedError(enRes.status, enRes.statusText));
            }
            return enRes.json();
        }).then(localeData => {
            CookieUtils.setLocaleCookie("en");
            return new I18nTools({localeData, locale});
        })
    });
}

const renderDom = (options, i18nTools, userInfo) => {
    const {store, routers, container} = options;
    hideLoadingAndShowAppContainer(options)
    ReactDOM.render(
        <I18nProvider i18n={i18nTools}>
            <UserProvider user={userInfo}>
                <Provider store={store}>
                    {routers}
                </Provider>
            </UserProvider>
        </I18nProvider>, container
    );
    changeTitleAndFavicon(options, i18nTools);
}

const changeTitleAndFavicon = (options, i18nTools) => {
    let faviconHref = `${options.config.contextPath}logo_PAXSTORE_color.png`;
    //let faviconTitle = i18nTools.l("title_pax_store");
    let faviconTitle = "";
    const marketInfo = options.store.getState().market;
    if (options.requireMarketValidation) {
        if ("admin" === options.config.clientId && marketInfo.adminMarketSetting) {
            if (marketInfo.adminMarketSetting.favicon) {
                faviconHref = marketInfo.adminMarketSetting.favicon;
            }
            if (marketInfo.adminMarketSetting.storeName) {
                faviconTitle = marketInfo.adminMarketSetting.storeName;
            }
        } else if ("portal" === options.config.clientId && marketInfo.portalMarketSetting) {
            if (marketInfo.portalMarketSetting.favicon) {
                faviconHref = marketInfo.portalMarketSetting.favicon;
            }
            if (marketInfo.portalMarketSetting.storeName) {
                faviconTitle = marketInfo.portalMarketSetting.storeName;
            }
        } else if ("developer" === options.config.clientId && marketInfo.developerMarketSetting) {
            if (marketInfo.developerMarketSetting.favicon) {
                faviconHref = marketInfo.developerMarketSetting.favicon;
            }
            if (marketInfo.developerMarketSetting.storeName) {
                faviconTitle = marketInfo.developerMarketSetting.storeName;
            }
        } else if ("account" === options.config.clientId) {
            faviconTitle = i18nTools.l("label_personal_center")
        }else if ("merchant" === options.config.clientId) {
            // faviconTitle = i18nTools.l("label_merchant_center")
            // faviconTitle = "Merchant Center"
            if (marketInfo.merchantMarketSetting.favicon) {
                faviconHref = marketInfo.merchantMarketSetting.favicon;
            }
            if (marketInfo.merchantMarketSetting.storeName) {
                faviconTitle = marketInfo.merchantMarketSetting.storeName;
            }
        }
    }
    const headEle = document.getElementsByTagName("head")[0];
    const link = document.querySelector("link[rel*='icon']") || document.createElement("link");
    link.type = "image/x-icon";
    link.rel = "shortcut icon";
    link.href = faviconHref;
    headEle.appendChild(link);

    const seoContent = `${marketInfo.name} ${marketInfo.domain} ${options.config.mainHostName} ${options.config.clientId}`;
    const metaKeywords = document.createElement("meta");
    metaKeywords.name = "keywords";
    metaKeywords.content = seoContent;
    headEle.appendChild(metaKeywords);

    const metaDesc = document.createElement("meta");
    metaDesc.name = "description";
    metaDesc.content = seoContent;
    headEle.appendChild(metaDesc);

    document.title = faviconTitle;
}

export const getCurrentDomain = config => {
    if (isPaxStoreMainHostAccess(config) && config.subDomainEnabled) {
        const hostname = window.location.hostname;
        return hostname.substring(0, hostname.indexOf("."));
    }
    return null;
}

const checkSubdomain = options => {
    if (options.disableMarketDomainAccess) {
        const appURL = options.config.moduleUrls[options.config.clientId];
        if (appURL && !window.location.href.startsWith(appURL)) {
            window.location.replace(appURL);
            return true;
        }
    }
    return false;
}

const loadReactApp = (options, i18nTools) => {
    const validateTokenSuccess = (options, i18nTools, userInfo) => {
        CookieUtils.setLoggedInCookie();
        if (options.handleSavedURL) processSavedURL();
        setTimeout(() => renderDom(options, i18nTools, userInfo), 0);
    };
    const validateTokenFalied = (options, i18nTools, error) => {
        StorageUtils.removeItem(STORAGE_KEY_TOKEN);
        if (error && (isNetworkError(error) || error.name === HttpFetchFailedError.ERROR_NAME)) {//PAXSTORE-1726
            renderError(options, i18nTools, error);
        } else {
            renderDom(options, i18nTools);
        }
    };
    const userLoginAction = data => options.store.dispatch(loginUserSuccess(data));

    try {
        const initTokenPromise = resolveCurrentAuthzCode(
            options, i18nTools, userLoginAction,
            validateTokenSuccess, validateTokenFalied
        );
        if (initTokenPromise) {
            initTokenPromise.catch(e => {
                if (e.name && SsoLoginTriedTimesExceedError.ERROR_NAME === e.name) {
                    renderError(options, i18nTools, e);
                } else {
                    validateTokenFalied(options, i18nTools, e);
                }
            });
        } else {
            if (options.handleLoggedInCookie && CookieUtils.isLoggedInCookieSet()) {
                // redirectToLogin(options.config.authServerUrl, options.config.clientId, getCurrentDomain(options.config), CookieUtils.getCurrentLocale());
                redirectToLogin2(options.config);
                return;
            }
            renderDom(options, i18nTools);
        }
    } catch (e) {
        if (e.name && SsoLoginTriedTimesExceedError.ERROR_NAME === e.name) {
            renderError(options, i18nTools, e);
        } else {
            validateTokenFalied(options, i18nTools);
        }
    }
}

const validateOptionsParam = options => {

    if (isNil(options)) {
        throw new Error("[bootstrapApp] options parameter cannot be null or undefined");
    }

    if (!options.container) {
        throw new Error("[bootstrapApp] container parameter in options is mandatory");
    }

    if (!options.store) {
        throw new Error("[bootstrapApp] store parameter in options is mandatory");
    }

    if (!options.config) {
        throw new Error("[bootstrapApp] config parameter in options is mandatory");
    }

    if (!options.routers) {
        throw new Error("[bootstrapApp] routers parameter in options is mandatory");
    }

    if (!getApiInstance()) {
        throw new Error("[bootstrapApp] API instance is not initialized");
    }

    if (!getSsoApiInstance()) {
        throw new Error("[bootstrapApp] SSO Auth/Token API instance is not initialized");
    }

    if (!isBoolean(options.requireMarketValidation)) {
        options.requireMarketValidation = false;
    }

    if (options.requireMarketValidation && (!options.loadMarketSuccessAction || !isFunction(options.loadMarketSuccessAction))) {
        throw new Error("[bootstrapApp] loadMarketSuccessAction parameter in options is mandatory and must be function if requireMarketValidation === true");
    }

    if (!isBoolean(options.handleLoggedInCookie)) {
        options.handleLoggedInCookie = false;
    }

    if (!isBoolean(options.handleSavedURL)) {
        options.handleSavedURL = false;
    }

    if (!isBoolean(options.disableMarketDomainAccess)) {
        options.disableMarketDomainAccess = false;
    }
}

const isBrowserUnsupported = () => {
    const browser = BrowserUtils.getBrowser();
    return (browser.name == "MSIE" || browser.name == "IE") && browser.version < 11;
}

/**
 * Load application.
 *
 * @export
 * @param {Object} options
 */
export default function bootstrapApp(options) {
    if (isBrowserUnsupported(options)) {
        hideLoadingAndShowAppContainer(options);
        ReactDOM.render(
            <MuiThemeProvider muiTheme={options.muiTheme}>
                <UnsupportedBrowserError/>
            </MuiThemeProvider>, options.container
        );
    } else {
        validateOptionsParam(options);
        if (isPaxStoreMainHostAccess(options.config) && checkSubdomain(options)) return;

        initI18n(options).then(i18nTools => {
            initMarketDc(options).then(() => {
                if (options.requireMarketValidation) {
                    initMarket(options).then(() => loadReactApp(options, i18nTools)).catch(e => {
                        hideLoadingAndShowAppContainer(options);
                        renderError(options, i18nTools, e);
                    })
                } else {
                    initI18n(options).then(i18nTools => loadReactApp(options, i18nTools));
                }
            }).catch(e => {
                hideLoadingAndShowAppContainer(options);
                renderError(options, i18nTools, e);
            })
        });
    }
}

/**
 * check if access is from main host or customized host, return true if it is from main host, otherwise return false
 * @param {*} config
 */
export const isPaxStoreMainHostAccess = config => {
    return window.location.hostname.endsWith(config.mainHostName);
}

const hideLoadingAndShowAppContainer = (options) => {
    if (options.loading) {
        options.loading.remove();
    }
    options.container.style.display = "block";
}
