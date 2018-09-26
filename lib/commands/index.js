module.exports = Object.assign({},
  require('./exec'),
  require('./read'),
  require('./info'),
  require('./lock'),
  require('./nonce'),
  require('./random'),
  require('./sign'),
  require('./verify')
)
