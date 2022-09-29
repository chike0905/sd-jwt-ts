"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSVCandSDDigests = exports.issueSDJWT = void 0;
const jose = __importStar(require("jose"));
const jose_1 = require("jose");
const crypto = __importStar(require("crypto"));
const SALT_BYTE_SIZE = 256 / 8;
// TODO: Now this returns combined format as single string (jwt + base64url encoded SVC) 
// It might be useful that issuer can select separated format (jwt and json format SVC?)
const issueSDJWT = (claims, privateKey, holderPublicKey, structured = false) => __awaiter(void 0, void 0, void 0, function* () {
    const { svc, sd_digests } = (0, exports.createSVCandSDDigests)(claims, structured);
    const sdJWTPayload = {
        sd_digests,
        hash_alg: 'sha-256' // TODO: tmp support only sha-256
    };
    if (holderPublicKey) {
        const sub_jwk = yield jose.exportJWK(holderPublicKey);
        Object.defineProperty(sdJWTPayload, 'sub_jwk', { value: sub_jwk, enumerable: true });
    }
    const jwt = yield new jose.SignJWT(sdJWTPayload)
        .setProtectedHeader({ alg: 'ES256' }) // TODO: tmp support only ES256
        .sign(privateKey);
    const encodedSVC = jose_1.base64url.encode(JSON.stringify(svc));
    const sd_jwt = jwt + '.' + encodedSVC;
    return sd_jwt;
});
exports.issueSDJWT = issueSDJWT;
const createSVCandSDDigests = (claims, structured = false) => {
    let svc = { sd_release: {} };
    let sd_digests = {};
    Object.keys(claims).map((key) => {
        let svc_item;
        let sd_digest_item;
        if (structured && claims[key] instanceof Object) {
            const { sd_digests, svc } = (0, exports.createSVCandSDDigests)(claims[key], structured);
            svc_item = svc.sd_release;
            sd_digest_item = sd_digests;
        }
        else {
            const salt = crypto.randomBytes(SALT_BYTE_SIZE);
            const svc_item_tuple = [jose_1.base64url.encode(salt), claims[key]];
            // NOTE: JSON.stringify does not encode with \ escape for quat
            svc_item = JSON.stringify(svc_item_tuple);
            sd_digest_item = jose_1.base64url.encode(crypto.createHash('sha256')
                .update(svc_item).digest());
        }
        Object.defineProperty(sd_digests, key, {
            value: sd_digest_item,
            enumerable: true,
        });
        Object.defineProperty(svc.sd_release, key, {
            value: svc_item,
            enumerable: true,
        });
    });
    return {
        sd_digests,
        svc
    };
};
exports.createSVCandSDDigests = createSVCandSDDigests;
//# sourceMappingURL=issue.js.map