module.exports = () => describe('Crypto', function () {
  require('./cipher')();
  require('./hash')();
  require('./random.js')();
  require('./crypto.js')();
  require('./elliptic.js')();
  require('./ecdh.js')();
  require('./pkcs5.js')();
  require('./aes_kw.js')();
  require('./gcm.js')();
  require('./eax.js')();
  require('./ocb.js')();
  require('./rsa.js')();
  require('./validate.js')();
  require('./hmac.js')();
});
