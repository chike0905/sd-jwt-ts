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
  holderPublicKey?: KeyLike
):
  Promise<string> => {
  const { svc, sd_digests } = createSVCandSDDigests(claims);

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

export const createSVCandSDDigests = (claims: SD_JWTClaims): {
  sd_digests: SD_DIGESTS,
  svc: SVC
} => {
  let svc = { sd_release: {} };
  let sd_digests = {};

  // TODO: recessively for structured claims
  Object.keys(claims).map((key: string) => {
    const salt: Buffer = crypto.randomBytes(SALT_BYTE_SIZE);
    const svc_item_tuple = [base64url.encode(salt), claims[key]];
    // NOTE: JSON.stringify does not encode with \ escape for quat
    const svc_item = JSON.stringify(svc_item_tuple);
    const sd_digest_item = base64url.encode(crypto.createHash('sha256')
      .update(svc_item).digest());
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
