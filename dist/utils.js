"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.separateJWTandSDJWTR = exports.separateJWTandSVC = void 0;
const jose_1 = require("jose");
const separateJWTandSVC = (sd_jwt) => {
    const splitted_sd_jwt = sd_jwt.split('.');
    if (splitted_sd_jwt.length !== 4)
        throw new Error('sd_jwt string should consist of 4 strings separated by comma.');
    const raw_svc = jose_1.base64url.decode(splitted_sd_jwt[3]).toString();
    const svc = JSON.parse(raw_svc);
    const jwt = splitted_sd_jwt.slice(0, 3).join('.');
    return { svc, jwt };
};
exports.separateJWTandSVC = separateJWTandSVC;
const separateJWTandSDJWTR = (sd_jwt) => {
    const splittedSdJwt = sd_jwt.split('.');
    if (splittedSdJwt.length !== 6)
        throw new Error('sd_jwt string should be presented as 6 strings separated by comma.');
    const sdJwt = splittedSdJwt.slice(0, 3).join('.');
    const sdJwtR = splittedSdJwt.slice(3).join('.');
    return { sdJwt, sdJwtR };
};
exports.separateJWTandSDJWTR = separateJWTandSDJWTR;
//# sourceMappingURL=utils.js.map