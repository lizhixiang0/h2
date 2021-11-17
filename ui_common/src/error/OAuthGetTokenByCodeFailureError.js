class OAuthGetTokenByCodeFailureError extends Error {

    static ERROR_NAME = "OAuthGetTokenByCodeFailureError";

    constructor(code, message = "Get access token by authz code failed.") {
        super(message);
        this.message = message;
        this.code = code;
        this.name = OAuthGetTokenByCodeFailureError.ERROR_NAME;
    }
}

export default OAuthGetTokenByCodeFailureError;