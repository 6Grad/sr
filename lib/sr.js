
var signedRequest = require('signed-request');

/**
 * Signed Requst Middleware
 *  - looks for req.param('sr') or header['X-sr'].
 *  - if valid req.srObj & req.sr are exposed.
 *  - sends back 403 if something goes wrong!
 */
module.exports = function (secret, ttl) {

  if(!secret) throw new Error('"secret" required');

  var ttl = ttl || 60*60*24; // a day

  function unauthorized(res) {
    res.send('unauthorized', 403);
  }

  return function (req, res, next) {

    var sr = req.param('sr', false) || req.header('X-sr', false);
    if (!sr) return unauthorized(res);

    try {
      req.srObj = signedRequest.parse(sr, secret, ttl);
      req.sr = sr;
      next();
    }catch(e) {
      return unauthorized(res);
    }
  };
};
