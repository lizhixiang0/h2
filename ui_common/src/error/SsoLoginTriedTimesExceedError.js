class SsoLoginTriedTimesExceedError extends Error {

    static ERROR_NAME = "SsoLoginTriedTimesExceedError";

    constructor(code, message = "Max SSO Login Tried Times Exceed.") {
        super(message);
        this.message = message;
        this.code = code;
        this.name = SsoLoginTriedTimesExceedError.ERROR_NAME;
    }
}

export default SsoLoginTriedTimesExceedError;