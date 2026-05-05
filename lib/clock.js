function nowSeconds(clockTimestamp) {
  return clockTimestamp || Math.floor(Date.now() / 1000);
}

module.exports = {
  nowSeconds,
};

