const JsonWebTokenError = require('../JsonWebTokenError');

function validateVerifyOptions(options) {
  if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
    throw new JsonWebTokenError('clockTimestamp must be a number');
  }

  if (options.nonce !== undefined && (typeof options.nonce !== 'string' || options.nonce.trim() === '')) {
    throw new JsonWebTokenError('nonce must be a non-empty string');
  }

  if (options.allowInvalidAsymmetricKeyTypes !== undefined && typeof options.allowInvalidAsymmetricKeyTypes !== 'boolean') {
    throw new JsonWebTokenError('allowInvalidAsymmetricKeyTypes must be a boolean');
  }
}

module.exports = {
  validateVerifyOptions,
};

