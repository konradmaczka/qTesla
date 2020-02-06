const {
  crypto_sign_keypair,
  crypto_sign,
  crypto_sign_open
} = require("./src/sign");

export const sign = crypto_sign;
export const signKeypair = crypto_sign_keypair;
export const signOpen = crypto_sign_open;
