class OAuthStateMismatchError extends Error {

    static ERROR_NAME = "OAuthStateMismatchError";

    constructor(code, message = "SSO State mismatch.") {
        super(message);
        this.message = message;
        this.code = code;
        this.name = OAuthStateMismatchError.ERROR_NAME;
    }
}

export default OAuthStateMismatchError;