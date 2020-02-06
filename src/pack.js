const { PARAM_N, PARAM_K, PARAM_Q_LOG } = require("./params");

function encode_sk(sk, s, e, seeds, hash_pk) {
  for (let i = 0; i < PARAM_N; i++) {
    sk[i] = s[i];
  }
  sk += PARAM_N;
  for (let k = 0; k < PARAM_K; k++) {
    for (let i = 1; i < PARAM_N; i++) {
      sk[k * PARAM_N + i] = e[k * PARAM_N + 1];
    }
  }
}

function encode_pk(pk, t, seedA) {
  let j = 0;
  let pt = pk;
  for (
    let i = 0;
    i < (PARAM_N * PARAM_K * PARAM_Q_LOG) / 32;
    i += PARAM_Q_LOG
  ) {
    pt[i] = t[j] | (t[j + 1] << 29);
    pt[i + 1] = (t[j + 1] >> 3) | (t[j + 2] << 26);
    pt[i + 2] = (t[j + 2] >> 6) | (t[j + 3] << 23);
    pt[i + 3] = (t[j + 3] >> 9) | (t[j + 4] << 20);
    pt[i + 4] = (t[j + 4] >> 12) | (t[j + 5] << 17);
    pt[i + 5] = (t[j + 5] >> 15) | (t[j + 6] << 14);
    pt[i + 6] = (t[j + 6] >> 18) | (t[j + 7] << 11);
    pt[i + 7] = (t[j + 7] >> 21) | (t[j + 8] << 8);
    pt[i + 8] = (t[j + 8] >> 24) | (t[j + 9] << 5);
    pt[i + 9] = (t[j + 9] >> 27) | (t[j + 10] << 2) | (t[j + 11] << 31);
    pt[i + 10] = (t[j + 11] >> 1) | (t[j + 12] << 28);
    pt[i + 11] = (t[j + 12] >> 4) | (t[j + 13] << 25);
    pt[i + 12] = (t[j + 13] >> 7) | (t[j + 14] << 22);
    pt[i + 13] = (t[j + 14] >> 10) | (t[j + 15] << 19);
    pt[i + 14] = (t[j + 15] >> 13) | (t[j + 16] << 16);
    pt[i + 15] = (t[j + 16] >> 16) | (t[j + 17] << 13);
    pt[i + 16] = (t[j + 17] >> 19) | (t[j + 18] << 10);
    pt[i + 17] = (t[j + 18] >> 22) | (t[j + 19] << 7);
    pt[i + 18] = (t[j + 19] >> 25) | (t[j + 20] << 4);
    pt[i + 19] = (t[j + 20] >> 28) | (t[j + 21] << 1) | (t[j + 22] << 30);
    pt[i + 20] = (t[j + 22] >> 2) | (t[j + 23] << 27);
    pt[i + 21] = (t[j + 23] >> 5) | (t[j + 24] << 24);
    pt[i + 22] = (t[j + 24] >> 8) | (t[j + 25] << 21);
    pt[i + 23] = (t[j + 25] >> 11) | (t[j + 26] << 18);
    pt[i + 24] = (t[j + 26] >> 14) | (t[j + 27] << 15);
    pt[i + 25] = (t[j + 27] >> 17) | (t[j + 28] << 12);
    pt[i + 26] = (t[j + 28] >> 20) | (t[j + 29] << 9);
    pt[i + 27] = (t[j + 29] >> 23) | (t[j + 30] << 6);
    pt[i + 28] = (t[j + 30] >> 26) | (t[j + 31] << 3);
    j += 32;
  }
}

function decode_pk(pk, seedA, pk_in) {
  let j = 0;
  let pt = pk_in;
  let pp = pk;
  let mask29 = (1 << PARAM_Q_LOG) - 1;
  for (let i = 0; i < PARAM_N * PARAM_K; i += 32) {
    pp[i] = pt[j] & mask29;
    pp[i + 1] = ((pt[j + 0] >> 29) | (pt[j + 1] << 3)) & mask29;
    pp[i + 2] = ((pt[j + 1] >> 26) | (pt[j + 2] << 6)) & mask29;
    pp[i + 3] = ((pt[j + 2] >> 23) | (pt[j + 3] << 9)) & mask29;
    pp[i + 4] = ((pt[j + 3] >> 20) | (pt[j + 4] << 12)) & mask29;
    pp[i + 5] = ((pt[j + 4] >> 17) | (pt[j + 5] << 15)) & mask29;
    pp[i + 6] = ((pt[j + 5] >> 14) | (pt[j + 6] << 18)) & mask29;
    pp[i + 7] = ((pt[j + 6] >> 11) | (pt[j + 7] << 21)) & mask29;
    pp[i + 8] = ((pt[j + 7] >> 8) | (pt[j + 8] << 24)) & mask29;
    pp[i + 9] = ((pt[j + 8] >> 5) | (pt[j + 9] << 27)) & mask29;
    pp[i + 10] = (pt[j + 9] >> 2) & mask29;
    pp[i + 11] = ((pt[j + 9] >> 31) | (pt[j + 10] << 1)) & mask29;
    pp[i + 12] = ((pt[j + 10] >> 28) | (pt[j + 11] << 4)) & mask29;
    pp[i + 13] = ((pt[j + 11] >> 25) | (pt[j + 12] << 7)) & mask29;
    pp[i + 14] = ((pt[j + 12] >> 22) | (pt[j + 13] << 10)) & mask29;
    pp[i + 15] = ((pt[j + 13] >> 19) | (pt[j + 14] << 13)) & mask29;
    pp[i + 16] = ((pt[j + 14] >> 16) | (pt[j + 15] << 16)) & mask29;
    pp[i + 17] = ((pt[j + 15] >> 13) | (pt[j + 16] << 19)) & mask29;
    pp[i + 18] = ((pt[j + 16] >> 10) | (pt[j + 17] << 22)) & mask29;
    pp[i + 19] = ((pt[j + 17] >> 7) | (pt[j + 18] << 25)) & mask29;
    pp[i + 20] = ((pt[j + 18] >> 4) | (pt[j + 19] << 28)) & mask29;
    pp[i + 21] = (pt[j + 19] >> 1) & mask29;
    pp[i + 22] = ((pt[j + 19] >> 30) | (pt[j + 20] << 2)) & mask29;
    pp[i + 23] = ((pt[j + 20] >> 27) | (pt[j + 21] << 5)) & mask29;
    pp[i + 24] = ((pt[j + 21] >> 24) | (pt[j + 22] << 8)) & mask29;
    pp[i + 25] = ((pt[j + 22] >> 21) | (pt[j + 23] << 11)) & mask29;
    pp[i + 26] = ((pt[j + 23] >> 18) | (pt[j + 24] << 14)) & mask29;
    pp[i + 27] = ((pt[j + 24] >> 15) | (pt[j + 25] << 17)) & mask29;
    pp[i + 28] = ((pt[j + 25] >> 12) | (pt[j + 26] << 20)) & mask29;
    pp[i + 29] = ((pt[j + 26] >> 9) | (pt[j + 27] << 23)) & mask29;
    pp[i + 30] = ((pt[j + 27] >> 6) | (pt[j + 28] << 26)) & mask29;
    pp[i + 31] = pt[j + 28] >> 3;
    j += 29;
  }
}
