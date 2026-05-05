const { nowSeconds } = require('../clock');

function applySignTimestampClaims(payload, isObjectPayload, options, timespan) {
  const timestamp = payload.iat || nowSeconds();

  if (options.noTimestamp) {
    delete payload.iat;
  } else if (isObjectPayload) {
    payload.iat = timestamp;
  }

  if (typeof options.notBefore !== 'undefined') {
    payload.nbf = timespan(options.notBefore, timestamp);
    if (typeof payload.nbf === 'undefined') {
      throw new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
    }
  }

  if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object') {
    payload.exp = timespan(options.expiresIn, timestamp);
    if (typeof payload.exp === 'undefined') {
      throw new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
    }
  }
}

function applySignOptionClaims(payload, options, optionsToPayload) {
  Object.keys(optionsToPayload).forEach(function (key) {
    const claim = optionsToPayload[key];
    if (typeof options[key] !== 'undefined') {
      if (typeof payload[claim] !== 'undefined') {
        throw new Error('Bad "options.' + key + '" option. The payload already has an "' + claim + '" property.');
      }
      payload[claim] = options[key];
    }
  });
}

module.exports = {
  applySignTimestampClaims,
  applySignOptionClaims,
};

