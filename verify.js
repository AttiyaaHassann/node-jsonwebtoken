const JsonWebTokenError = require('./lib/JsonWebTokenError');
const decode = require('./decode');
const timespan = require('./lib/timespan');
const validateAsymmetricKey = require('./lib/validateAsymmetricKey');
const jws = require('jws');
const {KeyObject} = require("crypto");
const { getVerifyDefaultAlgorithmsForKey } = require('./lib/algorithms');
const { normalizePublicKeyOrSecret } = require('./lib/keyUtils');
const { nowSeconds } = require('./lib/clock');
const { validateVerifyOptions } = require('./lib/options/verify');
const { validateSignaturePresenceAndKey } = require('./lib/policy/verifySignature');
const {
  validateNbf,
  validateExp,
  validateAudience,
  validateIssuer,
  validateSubject,
  validateJwtId,
  validateNonce,
  validateMaxAge,
} = require('./lib/claims/verify');

module.exports = function (jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) {
    callback = options;
    options = {};
  }

  if (!options) {
    options = {};
  }

  //clone this object since we are going to mutate it.
  options = Object.assign({}, options);

  let done;

  if (callback) {
    done = callback;
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }

  try {
    validateVerifyOptions(options);
  } catch (e) {
    return done(e);
  }

  const clockTimestamp = nowSeconds(options.clockTimestamp);

  if (!jwtString){
    return done(new JsonWebTokenError('jwt must be provided'));
  }

  if (typeof jwtString !== 'string') {
    return done(new JsonWebTokenError('jwt must be a string'));
  }

  const parts = jwtString.split('.');

  if (parts.length !== 3){
    return done(new JsonWebTokenError('jwt malformed'));
  }

  let decodedToken;

  try {
    decodedToken = decode(jwtString, { complete: true });
  } catch(err) {
    return done(err);
  }

  if (!decodedToken) {
    return done(new JsonWebTokenError('invalid token'));
  }

  const header = decodedToken.header;
  let getSecret;

  if(typeof secretOrPublicKey === 'function') {
    if(!callback) {
      return done(new JsonWebTokenError('verify must be called asynchronous if secret or public key is provided as a callback'));
    }

    getSecret = secretOrPublicKey;
  }
  else {
    getSecret = function(header, secretCallback) {
      return secretCallback(null, secretOrPublicKey);
    };
  }

  return getSecret(header, function(err, secretOrPublicKey) {
    if(err) {
      return done(new JsonWebTokenError('error in secret or public key callback: ' + err.message));
    }

    const hasSignature = parts[2].trim() !== '';

    try {
      validateSignaturePresenceAndKey(hasSignature, secretOrPublicKey, options.algorithms);
    } catch (e) {
      return done(e);
    }

    if (secretOrPublicKey != null && !(secretOrPublicKey instanceof KeyObject)) {
      try {
        secretOrPublicKey = normalizePublicKeyOrSecret(secretOrPublicKey);
      } catch (_) {
        return done(new JsonWebTokenError('secretOrPublicKey is not valid key material'))
      }
    }

    const allowedAlgorithms = options.algorithms || getVerifyDefaultAlgorithmsForKey(secretOrPublicKey);

    if (allowedAlgorithms.indexOf(decodedToken.header.alg) === -1) {
      return done(new JsonWebTokenError('invalid algorithm'));
    }

    if (header.alg.startsWith('HS') && secretOrPublicKey.type !== 'secret') {
      return done(new JsonWebTokenError((`secretOrPublicKey must be a symmetric key when using ${header.alg}`)))
    } else if (/^(?:RS|PS|ES)/.test(header.alg) && secretOrPublicKey.type !== 'public') {
      return done(new JsonWebTokenError((`secretOrPublicKey must be an asymmetric key when using ${header.alg}`)))
    }

    if (!options.allowInvalidAsymmetricKeyTypes) {
      try {
        validateAsymmetricKey(header.alg, secretOrPublicKey);
      } catch (e) {
        return done(e);
      }
    }

    let valid;

    try {
      valid = jws.verify(jwtString, decodedToken.header.alg, secretOrPublicKey);
    } catch (e) {
      return done(e);
    }

    if (!valid) {
      return done(new JsonWebTokenError('invalid signature'));
    }

    const payload = decodedToken.payload;

    const errors = [
      validateNbf(payload, options, clockTimestamp),
      validateExp(payload, options, clockTimestamp),
      validateAudience(payload, options),
      validateIssuer(payload, options),
      validateSubject(payload, options),
      validateJwtId(payload, options),
      validateNonce(payload, options),
      validateMaxAge(payload, options, clockTimestamp, timespan),
    ].filter(Boolean);

    if (errors.length > 0) {
      return done(errors[0]);
    }

    if (options.complete === true) {
      const signature = decodedToken.signature;

      return done(null, {
        header: header,
        payload: payload,
        signature: signature
      });
    }

    return done(null, payload);
  });
};
