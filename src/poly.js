const { cshake128 } = require("js-sha3");

const { zeta, zetainv } = require("./constants");

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
  PARAM_BARR_DIV
} = require("./params");

const RADIX32 = 32;

// Montgomery reduction
function m_reduce(a) {
  let u = (a * PARAM_QINV) & 0xffffffff;
  u *= PARAM_Q;
  a += u;
  return a >> 32;
}

// Barrett reduction
function b_reduce(a) {
  let u = (a * PARAM_BARR_MULT) >> PARAM_BARR_DIV;
  return a - u * PARAM_Q;
}

// Forward NTT transform
function ntt(a, w) {
  let NumoProblems = PARAM_N >> 1;
  let jTwiddle = 0;

  for (; NumoProblems > 0; NumoProblems >>= 1) {
    let j = 0;
    for (let jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems) {
      let W = w[jTwiddle++];
      for (j = jFirst; j < jFirst + NumoProblems; j++) {
        let temp = m_reduce(W * a[j + NumoProblems]);
        a[j + NumoProblems] = a[j] - temp;
        a[j + NumoProblems] += (a[j + NumoProblems] >> (RADIX32 - 1)) & PARAM_Q;
        a[j] = a[j] + temp - PARAM_Q;
        a[j] += (a[j] >> (RADIX32 - 1)) & PARAM_Q;
      }
    }
  }
}

// Inverse NTT transform
function nttinv(a, w) {
  let NumoProblems = 1,
    jTwiddle = 0;
  for (NumoProblems = 1; NumoProblems < PARAM_N; NumoProblems *= 2) {
    let jFirst,
      j = 0;
    for (jFirst = 0; jFirst < PARAM_N; jFirst = j + NumoProblems) {
      let W = w[jTwiddle++];
      for (j = jFirst; j < jFirst + NumoProblems; j++) {
        let temp = a[j];
        a[j] = b_reduce(temp + a[j + NumoProblems]);
        a[j + NumoProblems] = m_reduce(W * (temp - a[j + NumoProblems]));
      }
    }
  }
}

// Pointwise polynomial multiplication
function poly_pointwise(result, x, y) {
  for (let i = 0; i < PARAM_N; i++) {
    result[i] = m_reduce(x[i] * y[i]);
  }
}

function poly_ntt(x_ntt, x) {
  for (let i = 0; i < PARAM_N; i++) {
    x_ntt[i] = x[i];
  }
  ntt(x_ntt, zeta);
}

function poly_mul(result, x, y) {
  poly_pointwise(result, x, y);
  nttinv(result, zetainv);
}

function poly_add(result, x, y) {
  for (let i = 0; i < PARAM_N; i++) {
    result[i] = x[i] + y[i];
  }
}

function poly_add_correct(result, x, y) {
  for (let i = 0; i < PARAM_N; i++) {
    result[i] = x[i] + y[i];
    result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;
    result[i] -= PARAM_Q;
    result[i] += (result[i] >> (RADIX32 - 1)) & PARAM_Q;
  }
}

function poly_sub(result, x, y) {
  for (let i = 0; i < PARAM_N; i++) {
    result[i] = x[i] - y[i];
  }
}

function poly_sub_reduce(result, x, y) {
  for (let i = 0; i < PARAM_N; i++) {
    result[i] = b_reduce(x[i] - y[i]);
  }
}

function poly_uniform(a, seed) {
  let pos = 0;
  let i = 0;
  let nbytes = (PARAM_Q_LOG + 7) / 8;
  let nblocks = PARAM_GEN_A;
  let val1,
    val2,
    val3,
    val4,
    mask = (1 << PARAM_Q_LOG) - 1;
  let buf = new ArrayBuffer(SHAKE128_RATE * PARAM_GEN_A);
  let dmsp = 0;

  cshake128(buf, SHAKE128_RATE * PARAM_GEN_A, dmsp++, seed, 32);

  while (i < PARAM_K * PARAM_N) {
    if (pos > SHAKE128_RATE * nblocks - 4 * nbytes) {
      nblocks = 1;
      cshake128(buf, SHAKE128_RATE * nblocks, dmsp++, seed, 32);
      pos = 0;

      val1 = (buf + pos) & mask;
      pos += nbytes;
      val2 = (buf + pos) & mask;
      pos += nbytes;
      val3 = (buf + pos) & mask;
      pos += nbytes;
      val4 = (buf + pos) & mask;
      pos += nbytes;

      if (val1 < PARAM_Q && i < PARAM_K * PARAM_N) {
        a[i++] = m_reduce(val1 * PARAM_R2_INVN);
      }
      if (val2 < PARAM_Q && i < PARAM_K * PARAM_N) {
        a[i++] = m_reduce(val2 * PARAM_R2_INVN);
      }
      if (val3 < PARAM_Q && i < PARAM_K * PARAM_N) {
        a[i++] = m_reduce(val3 * PARAM_R2_INVN);
      }
      if (val4 < PARAM_Q && i < PARAM_K * PARAM_N) {
        a[i++] = m_reduce(val4 * PARAM_R2_INVN);
      }
    }
  }
}

function sparse_mul8(prod, s, pos_list, sign_list) {
  let pos;
  let t = s;

  for (let i = 0; i < PARAM_N; i++) {
    prod[i] = 0;
  }

  for (let i = 0; i < PARAM_H; i++) {
    pos = pos_list[i];
    for (let j = 0; j < pos; j++) {
      prod[j] = prod[j] - sign_list[i] * t[j + PARAM_N - pos];
    }
    for (letj = pos; j < PARAM_N; j++) {
      prod[j] = prod[j] + sign_list[i] * t[j - pos];
    }
  }
}

function sparse_mul32(prod, pk, pos_list, sign_list) {
  let pos;
  let temp = [0];

  for (let i = 0; i < PARAM_H; i++) {
    pos = pos_list[i];
    for (let j = 0; j < pos; j++) {
      temp[j] = temp[j] - sign_list[i] * pk[j + PARAM_N - pos];
    }
    for (let j = pos; j < PARAM_N; j++) {
      temp[j] = temp[j] + sign_list[i] * pk[j - pos];
    }
  }
  for (let i = 0; i < PARAM_N; i++) {
    prod[i] = b_reduce(temp[i]);
  }
}

module.exports = {
  m_reduce,
  b_reduce,
  ntt,
  nttinv,
  poly_ntt,
  poly_mul,
  poly_add,
  poly_add_correct,
  poly_sub,
  poly_sub_reduce,
  sparse_mul8,
  sparse_mul32,
  poly_uniform
};
