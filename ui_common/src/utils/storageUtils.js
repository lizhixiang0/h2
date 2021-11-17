export function setItem(key, value) {
    sessionStorage.setItem(key, value);
}

export function getItem(key) {
    return sessionStorage.getItem(key);
}

export function removeItem(key) {
    sessionStorage.removeItem(key);
}

export function getAndRemoveItem(key) {
    const value = getItem(key);
    removeItem(key);
    return value;
}

export function setLocalItem(key, value) {
    localStorage.setItem(key, value);
}

export function setOrderLocalItem(key, value) {
    if(localStorage !=null && localStorage.length>0) {
        for(var i=0;i<localStorage.length;i++) {
            if(localStorage.key(i).indexOf(key.substring(0,key.lastIndexOf("__")))>=0) {
                localStorage.removeItem(localStorage.key(i));
            }
        }
    }
    localStorage.setItem(key, value);
}

export function getLocalItem(key) {
    return localStorage.getItem(key);
}

export function removeLocalItem(key) {
    localStorage.removeItem(key);
}

export function getAndRemoveLocalItem(key) {
    const value = getLocalItem(key);
    removeLocalItem(key);
    return value;
}

