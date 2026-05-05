const PS_SUPPORTED = require('./psSupported');

const BASE_SUPPORTED_ALGS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512', 'none'];

function getSupportedAlgorithms() {
  const algs = BASE_SUPPORTED_ALGS.slice();
  if (PS_SUPPORTED) {
    // Keep ordering identical to existing sign.js behavior (insert after ES algorithms).
    algs.splice(3, 0, 'PS256', 'PS384', 'PS512');
  }
  return algs;
}

function getVerifyDefaultAlgorithmsForKey(key) {
  // Ordering is preserved to match existing verify.js behavior.
  const PUB_KEY_ALGS = ['RS256', 'RS384', 'RS512'];
  const EC_KEY_ALGS = ['ES256', 'ES384', 'ES512'];
  const RSA_KEY_ALGS = ['RS256', 'RS384', 'RS512'];
  const HS_ALGS = ['HS256', 'HS384', 'HS512'];

  if (PS_SUPPORTED) {
    PUB_KEY_ALGS.splice(PUB_KEY_ALGS.length, 0, 'PS256', 'PS384', 'PS512');
    RSA_KEY_ALGS.splice(RSA_KEY_ALGS.length, 0, 'PS256', 'PS384', 'PS512');
  }

  if (!key) return PUB_KEY_ALGS;
  if (key.type === 'secret') return HS_ALGS;
  if (['rsa', 'rsa-pss'].includes(key.asymmetricKeyType)) return RSA_KEY_ALGS;
  if (key.asymmetricKeyType === 'ec') return EC_KEY_ALGS;
  return PUB_KEY_ALGS;
}

module.exports = {
  getSupportedAlgorithms,
  getVerifyDefaultAlgorithmsForKey,
};

