import * as jose from 'jose';
import { base64url, KeyLike } from 'jose';
import * as crypto from 'crypto';

import { SD_DIGESTS, SD_JWTClaims, SVC } from './types';

const SALT_BYTE_SIZE = 256 / 8;

// TODO: Now this returns combined format as single string (jwt + base64url encoded SVC) 
// It might be useful that issuer can select separated format (jwt and json format SVC?)
export const issueSDJWT = async (
  claims: SD_JWTClaims,
  privateKey: KeyLike,
  holderPublicKey?: KeyLike,
  structured: boolean = false
):
  Promise<string> => {
  const { svc, sd_digests } = createSVCandSDDigests(claims, structured);

  const sdJWTPayload = {
    sd_digests,
    hash_alg: 'sha-256' // TODO: tmp support only sha-256
  };
  if (holderPublicKey) {
    const sub_jwk = await jose.exportJWK(holderPublicKey);
    Object.defineProperty(sdJWTPayload, 'sub_jwk', { value: sub_jwk, enumerable: true });
  }

  const jwt = await new jose.SignJWT(sdJWTPayload)
    .setProtectedHeader({ alg: 'ES256' }) // TODO: tmp support only ES256
    .sign(privateKey);

  const encodedSVC = base64url.encode(JSON.stringify(svc));

  const sd_jwt = jwt + '.' + encodedSVC;

  return sd_jwt;
};

export const createSVCandSDDigests = (
  claims: SD_JWTClaims,
  structured: boolean = false
): {
  sd_digests: SD_DIGESTS,
  svc: SVC
} => {
  let svc = { sd_release: {} };
  let sd_digests = {};

  Object.keys(claims).map((key: string) => {
    let svc_item;
    let sd_digest_item;
    if (structured && claims[key] instanceof Object) {
      const { sd_digests, svc } =
        createSVCandSDDigests(claims[key] as SD_JWTClaims, structured);
      svc_item = svc.sd_release;
      sd_digest_item = sd_digests;
    } else {
      const salt: Buffer = crypto.randomBytes(SALT_BYTE_SIZE);
      const svc_item_tuple = [base64url.encode(salt), claims[key]];
      // NOTE: JSON.stringify does not encode with \ escape for quat
      svc_item = JSON.stringify(svc_item_tuple);
      sd_digest_item = base64url.encode(crypto.createHash('sha256')
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
  }
};
