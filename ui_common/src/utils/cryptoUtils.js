import {JSEncrypt} from "jsencrypt"
import {getItem} from "./storageUtils";
import CryptoJS from "crypto-js/crypto-js"
import {STORAGE_KEY_TOKEN} from "./ssoAuthUtils";

let encrypt = undefined;

export function encryptPassword(plainPassword) {
    if (encrypt == undefined) {
        throw new Error("Password encrypt is not initialized");
    }
    if (!plainPassword || plainPassword.trim() == "") {
        return plainPassword;
    }
    if (plainPassword.trim().length > 128) {
        return plainPassword;
    }
    return encrypt.encrypt(plainPassword.trim());
}

export function initPasswordEncrypt(market) {
    if (encrypt == undefined) {
        encrypt = new JSEncrypt();
        if (market && market.passwordPublicKey) {
            encrypt.setPublicKey(market.passwordPublicKey);
        } else {
            throw new Error("Password public key is not initialized");
        }
    }
}

export function encryptParameter(parameter) {
    let token = getItem(STORAGE_KEY_TOKEN);
    if (!token) {
        return parameter;
    }
    if (token.startsWith("Bearer ")) {
        token = token.substring(7);
    }
    if (parameter == undefined || parameter == "" || isEncryptedParameter(parameter)) {
        return parameter;
    }
    const encryptedData = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(parameter), CryptoJS.MD5(token), {
        mode   : CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return encryptedData.ciphertext.toString();
}

export function decryptParameter(encryptedParameter) {
    let token = getItem(STORAGE_KEY_TOKEN);
    if (!token) {
        return encryptedParameter;
    }
    if (token.startsWith("Bearer ")) {
        token = token.substring(7);
    }
    const encryptedHexParameter = CryptoJS.enc.Hex.parse(encryptedParameter);
    const decryptedData = CryptoJS.AES.decrypt(CryptoJS.enc.Base64.stringify(encryptedHexParameter), CryptoJS.MD5(token), {
        mode   : CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return decryptedData.toString();
}

export function isEncryptedParameter(parameter) {
    if (parameter == undefined || parameter == "" || parameter.trim() == "") {
        return false;
    }
    return /^•+$/.test(parameter);
}

export function maskParameter(parameter) {
    if (parameter == undefined || parameter == "" || parameter.trim() == "") {
        return parameter;
    }
    return new Array(parameter.length + 1).join("•");
}