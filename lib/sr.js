
var signedRequest = require('signed-request');

/**
 * Signed Requst Middleware
 *  - specify where to find the signed request parameter. (defaults to req.param('sr') or header['X-sr']).
 *  - if valid req.srObj & req.sr are exposed.
 *  - sends back 403 if something goes wrong!
 */
module.exports = function (secret, ttl, find) {

  if(!secret) throw new Error('"secret" required');

  //defaults
  var ttl = ttl || 60*60*24 // a day
    , find = find || function (req) { return req.param('xr') || req.header('X-sr'); };

  function unauthorized(res) {
    res.send('unauthorized', 403);
  }
  
  return function (req, res, next) {

    //find the signed request
    var sr = find(req);
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
