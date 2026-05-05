const JsonWebTokenError = require('../JsonWebTokenError');

function validateSignaturePresenceAndKey(hasSignature, key, algorithmsOption) {
  if (!hasSignature && key) {
    throw new JsonWebTokenError('jwt signature is required');
  }

  if (hasSignature && !key) {
    throw new JsonWebTokenError('secret or public key must be provided');
  }

  if (!hasSignature && !algorithmsOption) {
    throw new JsonWebTokenError('please specify "none" in "algorithms" to verify unsigned tokens');
  }
}

module.exports = {
  validateSignaturePresenceAndKey,
};

