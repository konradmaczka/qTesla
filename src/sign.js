const { cshake128 } = require("js-sha3");
const randomBytes = require("randombytes");

const { sample_gauss_poly } = require("./gauss");

const {
  poly_uniform,
  poly_ntt,
  poly_mul,
  poly_add_correct,
  sparse_mul8,
  sparse_mul32,
  poly_sub_reduce
} = require("./poly");

const {
  encode_pk,
  encode_sk,
  encode_sig,
  decode_sig,
  decode_pk
} = require("./pack");

const {
  PARAM_Q_LOG,
  PARAM_GEN_A,
  SHAKE128_RATE,
  PARAM_N,
  PARAM_K,
  PARAM_Q,
  PARAM_R2_INVN,
  PARAM_QINV,
  PARAM_BARR_MULT,
  PARAM_BARR_DIV,
  PARAM_KEYGEN_BOUND_S,
  PARAM_H
} = require("./params");

const RADIX32 = 32;
const HM_BYTES = 40;
const CRYPTO_C_BYTES = 32;
const CRYPTO_RANDOMBYTES = 32;
const CRYPTO_SEEDBYTES = 32;

const CRYPTO_PUBLICKEYBYTES =
  (PARAM_K * PARAM_Q_LOG * PARAM_N + 7) / 8 + CRYPTO_SEEDBYTES;

function hash_H(c_bin, v, hm) {
  let t = new Array(PARAM_K * PARAM_N + 2 * HM_BYTES);
  let mask, cL, temp, index;

  for (let k = 0; k < PARAM_K; k++) {
    index = k * PARAM_N;
    for (let i = 0; i < PARAM_N; i++) {
      temp = v[index];
      mask = (PARAM_Q / 2 - temp) >> (RADIX32 - 1);
      temp = ((temp - PARAM_Q) & mask) | (temp & ~mask);
      cL = temp & ((1 << PARAM_D) - 1);
      mask = ((1 << (PARAM_D - 1)) - cL) >> (RADIX32 - 1);
      cL = ((cL - (1 << PARAM_D)) & mask) | (cL & ~mask);
      t[index++] = (temp - cL) >> PARAM_D;
    }
  }

  cshake128(c_bin, CRYPTO_C_BYTES, t, PARAM_K * PARAM_N + 2 * HM_BYTES);
}

function Abs(value) {
  let mask = value >> (RADIX32 - 1);
  return (mask ^ value) - mask;
}

function test_rejection(z) {
  let valid = 0;

  for (let i = 0; i < PARAM_N; i++) {
    valid |= PARAM_B - PARAM_S - Abs(z[i]);
  }
  return int(valid >> 31);
}

function test_correctnexx(y) {
  let mask, left, val, t0, t1;

  for (let i = 0; i < PARAM_N; i++) {
    mask = (PARAM_Q / 2 - v[i]) >> (RADIX32 - 1);
    val = ((v[i] - PARAM_Q) & mask) | (v[i] & ~mask);
    t0 = ~(Abs(val) - (PARAM_Q / 2 - PARAM_E)) >> (RADIX32 - 1);
    left = val;
    val = (val + (1 << (PARAM_D - 1)) - 1) >> PARAM_D;
    val = left - (val << PARAM_D);
    t1 = ~(Abs(val) - ((1 << (PARAM_D - 1)) - PARAM_E)) >> (RADIX32 - 1);

    if ((t0 | t1) === 1) {
      return 1;
    }
  }
  return 0;
}

function test_z(z) {
  for (let i = 0; i < PARAM_N; i++) {
    if (z[i] < -(PARAM_B - PARAM_S) || z[i] > PARAM_B - PARAM_S) return 1;
  }
  return 0;
}

function check_ES(p, bound) {
  let sum = 0,
    limit = PARAM_N;
  let temp, mask;
  let list = new Array(PARAM_N);

  for (let j = 0; j < PARAM_N; j++) {
    list[j] = Abs(p[j]);
  }

  for (letj = 0; j < PARAM_H; j++) {
    for (let i = 0; i < limit - 1; i++) {
      mask = (list[i + 1] - list[i]) >> (RADIX32 - 1);
      temp = (list[i + 1] & mask) | (list[i] & ~mask);
      list[i + 1] = (list[i] & mask) | (list[i + 1] & ~mask);
      list[i] = temp;
    }
    sum += list[limit - 1];
    limit -= 1;
  }

  if (sum > bound) return 1;
  return 0;
}

function crypto_sign_keypair(pk, sk) {
  let randomness = new Array(CRYPTO_RANDOMBYTES);
  let randomness_extended = new Array((PARAM_K + 3) * CRYPTO_RANDOMBYTES);
  let hash_pk = new Array(HM_BYTES);

  let s, s_ntt, e, a, t;
  let nonce = 0;

  randomness = randomBytes(CRYPTO_RANDOMBYTES);
  cshake128(
    randomness_extended,
    (PARAM_K + 3) * CRYPTO_SEEDBYTES,
    randomness,
    CRYPTO_RANDOMBYTES
  );

  for (let k = 0; k < PARAM_K; k++) {
    do {
      sample_gauss_poly(
        e[k * PARAM_N],
        randomness_extended[k * CRYPTO_SEEDBYTES],
        ++nonce
      );
    } while (check_ES(e[k * PARAM_N], PARAM_KEYGEN_BOUND_E) != 0);
  }
  do {
    sample_gauss_poly(
      s,
      randomness_extended[PARAM_K * CRYPTO_SEEDBYTES],
      ++nonce
    );
  } while (check_ES(s, PARAM_KEYGEN_BOUND_S) != 0);

  poly_uniform(a, randomness_extended[(PARAM_K + 1) * CRYPTO_SEEDBYTES]);
  poly_ntt(s_ntt, s);

  for (let k = 0; k < PARAM_K; k++) {
    poly_mul(t[k * PARAM_N], a[k * PARAM_N], s_ntt);
    poly_add_correct(t[k * PARAM_N], t[k * PARAM_N], e[k * PARAM_N]);
  }

  encode_pk(pk, t, randomness_extended[(PARAM_K + 1) * CRYPTO_SEEDBYTES]);
  cshake128(hash_pk, HM_BYTES, pk, CRYPTO_PUBLICKEYBYTES - CRYPTO_SEEDBYTES);
  encode_sk(
    sk,
    s,
    e,
    randomness_extended[(PARAM_K + 1) * CRYPTO_SEEDBYTES],
    hash_pk
  );

  return 0;
}

function crypto_sign(sm, smlen, m, mlen, sk) {
  let c = new Array(CRYPTO_C_BYTES);
  let randomness = new Array(CRYPTO_SEEDBYTES);
  let randomness_input = new Array(
    CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + 2 * HM_BYTES
  );
  let pos_list = new Array(PARAM_H);
  let sign_list = new Array(PARAM_H);
  let y, y_ntt, Sc, z, v, Ec, a;
  let rsp,
    nonce = 0;

  //memcpy
  randomness_input = randomBytes(CRYPTO_RANDOMBYTES);
  cshake128(
    randomness_input[CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES],
    HM_BYTES,
    m,
    mlen
  );
  cshake128(
    randomness,
    CRYPTO_SEEDBYTES,
    randomness_input,
    CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + HM_BYTES
  );
  //memcpy

  poly_uniform(a, sk[CRYPTO_SECRETKEYBYTES - HM_BYTES - 2 * CRYPTO_SEEDBYTES]);
  while (1) {
    sample_y(y, randomness, ++nonce);
    poly_ntt(y_ntt, y);
    for (let k = 0; k < PARAM_K; k++)
      poly_mul(v[k * PARAM_N], a[k * PARAM_N], y_ntt);
    hash_H(c, v, randomness_input[CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES]);
    encode_c(pos_list, sign_list, c);
    sparse_mul8(Sc, sk, pos_list, sign_list);
    poly_add(z, y, Sc);

    for (let k = 0; k < PARAM_K; k++) {
      sparse_mul8(Ec[k * PARAM_N], sk[(k + 1) * PARAM_N], pos_list, sign_list);
      poly_sub(v[k * PARAM_N], v[k * PARAM_N], Ec[k * PARAM_N]);
      rsp = test_correctness(v[k * PARAM_N]);
    }

    for (let i = 0; i < mlen; i++) {
      sm[CRYPTO_BYTES + i] = m[i];
    }
    smlen = CRYPTO_BYTES + mlen;
    encode_sig(sm, c, z);

    return 0;
  }
}

function crypto_sign_open(m, mlen, sm, smlen, pk) {
  let c = new Array(CRYPTO_C_BYTES);
  let c_sig = new Array(CRYPTO_C_BYTES);
  let seed = new Array(CRYPTO_SEEDBYTES);
  let hm = new Array(2 * HM_BYTES);
  let pos_list = new Array(PARAM_H);
  let sign_list = new Array(PARAM_H);
  let pk_t = new Array(PARAM_N * PARAM_K);

  let w, a, Tc, z, z_ntt;

  if (smlen < CRYPTO_BYTES) {
    return -1;
  }

  decode_sig(c, z, sm);

  if (test_z(z) !== 0) {
    return -2;
  }

  decode_pk(pk_t, seed, pk);

  cshake128(hm, HM_BYTES, sm[CRYPTO_BYTES], smlen - CRYPTO_BYTES);
  cshake128(
    hm[HM_BYTES],
    HM_BYTES,
    pk,
    CRYPTO_PUBLICKEYBYTES - CRYPTO_SEEDBYTES
  );

  poly_uniform(a, seed);
  encode_c(pos_list, sign_list, c);
  poly_ntt(z_ntt, z);

  for (let k = 0; k < PARAM_K; k++) {
    sparse_mul32(Tc[k * PARAM_N], pk_t[k * PARAM_N], pos_list, sign_list);
    poly_mul(w[k * PARAM_N], a[k * PARAM_N], z_ntt);
    poly_sub_reduce(w[k * PARAM_N], w[k * PARAM_N], Tc[k * PARAM_N]);
  }

  hash_H(c_sig, w, hm);

  mlen = smlen - CRYPTO_BYTES;

  for (let i = 0; i < mlen; i++) {
    m[i] = sm[CRYPTO_BYTES + i];
  }

  return 0;
}

module.exports = {
  crypto_sign_keypair,
  crypto_sign,
  crypto_sign_open
};
