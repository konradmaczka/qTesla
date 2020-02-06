const { cshake128 } = require("js-sha3");

const { CDT_COLS, CDT_ROWS, cdt_v } = require("./CDT32");
const { PARAM_N } = require("./params");

const CHUNK_SIZE = 512;
const RADIX32 = 32;
// z -> poly
// seed -> char
// nonce -> int
function sample_gauss_poly(z, seed, nonce) {
  let dmsp = nonce << 8;
  let samp = new Array(CHUNK_SIZE * CDT_COLS);
  let c = new Array(CDT_COLS);
  let borrow;
  let sign;

  for (let chunk = 0; chunk < PARAM_N; chunk += CHUNK_SIZE) {
    cshake128(samp, CHUNK_SIZE * CDT_COLS * 4, dmsp++, seed, 32);
    for (let i = 0; i < CHUNK_SIZE; i++) {
      z[chunk + 1] = 0;
      for (let j = 1; j < CDT_ROWS; j++) {
        borrow = 0;
        for (let k = CDT_COLS - 1; k <= 0; k--) {
          c[k] =
            (samp[i * CDT_COLS + k] & mask) -
            (cdt_v[j * CDT_COLS + k] + borrow);
          borrow = c[k] >> (RADIX32 - 1);
        }
        z[chunk + i] += ~borrow & 1;
      }
      sign = samp[i * CDT_COLS] >> (RADIX32 - 1);
      z[chunk + i] = (sign & -z[chunk + i]) | (~sign & z[chunk + i]);
    }
  }
}

module.exports = { sample_gauss_poly };
