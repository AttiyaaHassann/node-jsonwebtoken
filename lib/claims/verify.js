const JsonWebTokenError = require('../JsonWebTokenError');
const NotBeforeError = require('../NotBeforeError');
const TokenExpiredError = require('../TokenExpiredError');

function validateNbf(payload, options, clockTimestamp) {
  if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') {
      return new JsonWebTokenError('invalid nbf value');
    }
    if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
      return new NotBeforeError('jwt not active', new Date(payload.nbf * 1000));
    }
  }
}

function validateExp(payload, options, clockTimestamp) {
  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
      return new JsonWebTokenError('invalid exp value');
    }
    if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
      return new TokenExpiredError('jwt expired', new Date(payload.exp * 1000));
    }
  }
}

function validateAudience(payload, options) {
  if (!options.audience) return;

  const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
  const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

  const match = target.some(function (targetAudience) {
    return audiences.some(function (audience) {
      return audience instanceof RegExp ? audience.test(targetAudience) : audience === targetAudience;
    });
  });

  if (!match) {
    return new JsonWebTokenError('jwt audience invalid. expected: ' + audiences.join(' or '));
  }
}

function validateIssuer(payload, options) {
  if (!options.issuer) return;

  const invalid_issuer =
    (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
    (Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss) === -1);

  if (invalid_issuer) {
    return new JsonWebTokenError('jwt issuer invalid. expected: ' + options.issuer);
  }
}

function validateSubject(payload, options) {
  if (!options.subject) return;
  if (payload.sub !== options.subject) {
    return new JsonWebTokenError('jwt subject invalid. expected: ' + options.subject);
  }
}

function validateJwtId(payload, options) {
  if (!options.jwtid) return;
  if (payload.jti !== options.jwtid) {
    return new JsonWebTokenError('jwt jwtid invalid. expected: ' + options.jwtid);
  }
}

function validateNonce(payload, options) {
  if (!options.nonce) return;
  if (payload.nonce !== options.nonce) {
    return new JsonWebTokenError('jwt nonce invalid. expected: ' + options.nonce);
  }
}

function validateMaxAge(payload, options, clockTimestamp, timespan) {
  if (!options.maxAge) return;

  if (typeof payload.iat !== 'number') {
    return new JsonWebTokenError('iat required when maxAge is specified');
  }

  const maxAgeTimestamp = timespan(options.maxAge, payload.iat);
  if (typeof maxAgeTimestamp === 'undefined') {
    return new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
  }
  if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
    return new TokenExpiredError('maxAge exceeded', new Date(maxAgeTimestamp * 1000));
  }
}

module.exports = {
  validateNbf,
  validateExp,
  validateAudience,
  validateIssuer,
  validateSubject,
  validateJwtId,
  validateNonce,
  validateMaxAge,
};

