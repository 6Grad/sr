
/**
 * Signed Requst Middleware
 */

var signedRequest = require('signed-request');

/**
 * `find` signed request parameter value and expose
 * the decoded/validated object to req.srObj (original value to req.sr).
 *
 * send 403 'unauthorized' if something goes wrong.
 *
 *  @param {String} secret
 *  @param {Object} options (optional)
 */
module.exports = function (secret, options) {

  if(!secret) throw new Error('"secret" required');
  //defaults
  var options = options || {}
    , ttl = options.ttl || 60*60*24 // a day
    , required = options.required || true
    , find = options.find || function (req) { return req.param('sr') || req.header('X-sr'); };

  function unauthorized(res) {
    res.send('unauthorized', 403);
  }
  
  return function (req, res, next) {

    //find the signed request parameter value
    var sr = find(req);
    if (!sr) {
      if (required) return unauthorized(res);
      else return next();
    }

    try {
      req.srObj = signedRequest.parse(sr, secret, ttl);
      req.sr = sr;
      next();
    }catch(e) {
      return unauthorized(res);
    }
  };
};
