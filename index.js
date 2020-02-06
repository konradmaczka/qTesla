const {
  crypto_sign_keypair,
  crypto_sign,
  crypto_sign_open
} = require("./src/sign");

module.exports = {
  sign: crypto_sign,
  signKeypair: crypto_sign_keypair,
  signOpen: crypto_sign_open
};
