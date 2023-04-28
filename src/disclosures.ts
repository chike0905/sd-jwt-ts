import * as crypto from 'crypto';
import { base64url } from 'jose';

const SALT_BYTE_SIZE = 256 / 8;

export const createDisclosure = (key: string, value: any): string => {
  const salt: Buffer = crypto.randomBytes(SALT_BYTE_SIZE);
  const disclosureArray = [base64url.encode(salt), key, value];
  const disclosure = base64url.encode(JSON.stringify(disclosureArray))
  return disclosure;
};

export const hashDisclosure = (disclosure: string): string => {
  return base64url.encode(crypto.createHash('sha256').update(disclosure).digest());
};

export const createDecoyDigest = (): string => {
  // From Spec: It is RECOMMENDED to create the decoy digests by hashing over a cryptographically secure random number.
  const randomNumber: Buffer = crypto.randomBytes(SALT_BYTE_SIZE);
  return base64url.encode(crypto.createHash('sha256').update(randomNumber).digest());
}
