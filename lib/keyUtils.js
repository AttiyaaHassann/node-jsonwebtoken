const { KeyObject, createSecretKey, createPrivateKey, createPublicKey } = require('crypto');

function normalizePrivateKey(secretOrPrivateKey) {
  if (secretOrPrivateKey == null) return secretOrPrivateKey;
  if (secretOrPrivateKey instanceof KeyObject) return secretOrPrivateKey;

  try {
    return createPrivateKey(secretOrPrivateKey);
  } catch (_) {
    return createSecretKey(
      typeof secretOrPrivateKey === 'string'
        ? Buffer.from(secretOrPrivateKey)
        : secretOrPrivateKey
    );
  }
}

function normalizePublicKeyOrSecret(secretOrPublicKey) {
  if (secretOrPublicKey == null) return secretOrPublicKey;
  if (secretOrPublicKey instanceof KeyObject) return secretOrPublicKey;

  try {
    return createPublicKey(secretOrPublicKey);
  } catch (_) {
    return createSecretKey(
      typeof secretOrPublicKey === 'string'
        ? Buffer.from(secretOrPublicKey)
        : secretOrPublicKey
    );
  }
}

module.exports = {
  normalizePrivateKey,
  normalizePublicKeyOrSecret,
};

