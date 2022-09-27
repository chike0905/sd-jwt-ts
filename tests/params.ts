import { importJWK, KeyLike } from "jose";

export const PRIVATE_KEY_JWK = {
  kty: 'EC',
  x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
  y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
  crv: 'P-256',
  d: 'fWfGrvu1tUqnyYHrdlpZiBsxkMoeim3EleoPEafV_yM'
};

export const PUBLIC_KEY_JWK = {
  kty: 'EC',
  x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
  y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
  crv: 'P-256'
};

export const ISSUER_KEYPAIR = {
  PUBLIC_KEY_JWK: {
    kty: 'EC',
    x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
    y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
    crv: 'P-256'
  },
  PRIVATE_KEY_JWK: {
    kty: 'EC',
    x: 'QxM0mbg6Ow3zTZZjKMuBv-Be_QsGDfRpPe3m1OP90zk',
    y: 'aR-Qm7Ckg9TmtcK9-miSaMV2_jd4rYq6ZsFRNb8dZ2o',
    crv: 'P-256',
    d: 'fWfGrvu1tUqnyYHrdlpZiBsxkMoeim3EleoPEafV_yM'
  }
}

export const HOLDER_KEYPAIR = {
  PUBLIC_KEY_JWK: {
    kty: 'EC',
    x: 'Juiif_Dm5T-xVYbcNZ72jSAk4t4ij5Bmgl7WGKO0uJQ',
    y: 'nqGkThWyZYFdQ3nnpkeoeey7edX7BV6-C9R3mOf1x1M',
    crv: 'P-256'
  },
  PRIVATE_KEY_JWK: {
    kty: 'EC',
    x: 'Juiif_Dm5T-xVYbcNZ72jSAk4t4ij5Bmgl7WGKO0uJQ',
    y: 'nqGkThWyZYFdQ3nnpkeoeey7edX7BV6-C9R3mOf1x1M',
    crv: 'P-256',
    d: 'mNCbN_oN0w43TgR_-wxa4tbZ7D6hTevIk1UtbiHXHXU'
  }
};

export const PAYLOAD = {
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  // "address": {
  //   "street_address": "123 Main St",
  //   "locality": "Anytown",
  //   "region": "Anystate",
  //   "country": "US"
  // },
  "birthdate": "1940-01-01"
};

export const SAMPLE_SD_JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzZF9kaWdlc3RzIjp7InN1YiI6InExNV81X3RvU1FZUlRhbGU3MDJTdDRPbld4Wl9rTDNiT2xaa3I4dlpFTmMiLCJnaXZlbl9uYW1lIjoiQlk1S1hvdk9oa0RTWXZZY0c2M244VUZXN1NfZTBtdzhGNXkwd1oyS2pwWSIsImZhbWlseV9uYW1lIjoiODNTQi1zUkZxYkU3MU9DTzVFUkJXT2RPWXVRODhaelpGbTZ5ekRoSndKTSIsImVtYWlsIjoid1NSd1RLYjV3Mk5rZ2xNbGJCXzg5T2V6OGk4YU9ONWU3NXFBZU1fQmJnNCIsInBob25lX251bWJlciI6IlAxelhBWU5UMnh3bjN3cHF2c253d3ZCUWdfbnJWb2dLUG1rVEc4dU9iRUEiLCJiaXJ0aGRhdGUiOiJGaEtpckRoQ2lNdWc1ZzF1NmJWSzlSRHdSWjBSOGpvMlNkS0pZMGxmeDVBIn0sImhhc2hfYWxnIjoic2hhLTI1NiJ9.nsKJe448P8MujtILWKxm_oqAF0i2SEo0F76s_oJwbvAsdHPbXdmaPkt5J2QsJ_kAS28nnrWiJO4d6eTG20bFLw.eyJzZF9yZWxlYXNlIjp7InN1YiI6IltcIjU4ckFnQW5Kc1FWMDl0YzN5T2dPNkYzZzZVVFd2VnZPa19WTVdXTHlpa0FcIixcIjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyY1wiXSIsImdpdmVuX25hbWUiOiJbXCJKSkpETEZaYXJoNWxnMk92ZUd6WHpBV1BQTElqWTVEMEg5UTB3S2tRVldRXCIsXCJKb2huXCJdIiwiZmFtaWx5X25hbWUiOiJbXCJFQXp1YWdkV3pIM1Q4cFRocXlsRnVqXzczWHZ2aGhGX0lHbFVaRURkcTlzXCIsXCJEb2VcIl0iLCJlbWFpbCI6IltcIkVGMkxLNEttMi0tUjJCQTNOS0tESkNodXc3eFEwU0NVNDMxdlVUZmlhdE1cIixcImpvaG5kb2VAZXhhbXBsZS5jb21cIl0iLCJwaG9uZV9udW1iZXIiOiJbXCJYSUxrc3JFMElLc1RVdlNMTkFHTnpzc0hQMlhzdS12bk5iNnhJdU9Wb084XCIsXCIrMS0yMDItNTU1LTAxMDFcIl0iLCJiaXJ0aGRhdGUiOiJbXCJNbzZoNkppOS1YQmxhVHgwZUZzY0YzWl83bjVSWDNLRE03WmM4N1g1NndBXCIsXCIxOTQwLTAxLTAxXCJdIn19";

export type Entity = {
  PUBLIC_KEY: KeyLike,
  PRIVATE_KEY: KeyLike
}

export const importKeyPairForIssuerAndHolder = async () => {
  const ISSUER = {
    PUBLIC_KEY: await importJWK(ISSUER_KEYPAIR.PUBLIC_KEY_JWK, 'ES256') as KeyLike,
    PRIVATE_KEY: await importJWK(ISSUER_KEYPAIR.PRIVATE_KEY_JWK, 'ES256') as KeyLike,
  };

  const HOLDER = {
    PUBLIC_KEY: await importJWK(HOLDER_KEYPAIR.PRIVATE_KEY_JWK, 'ES256') as KeyLike,
    PRIVATE_KEY: await importJWK(HOLDER_KEYPAIR.PRIVATE_KEY_JWK, 'ES256') as KeyLike,
  };
  return { ISSUER, HOLDER }
}