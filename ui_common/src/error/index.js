import OAuthStateMismatchError from "./OAuthStateMismatchError";
import OAuthGetTokenByCodeFailureError from "./OAuthGetTokenByCodeFailureError";
import SsoLoginTriedTimesExceedError from "./SsoLoginTriedTimesExceedError";

export {
    OAuthStateMismatchError,
    OAuthGetTokenByCodeFailureError,
    SsoLoginTriedTimesExceedError,
};

export const isNetworkError = error => {

    return error && error.message && (
        error.message === "Failed to fetch" || //chrome
        error.message === "NetworkError when attempting to fetch resource." || //firefox
        error.message === "Network request failed" || // safari, ie
        error.message === "Type error" //safari
    );
}