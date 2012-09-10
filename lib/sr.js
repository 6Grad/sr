
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
 *  @param {Number} ttl
 *  @param {Function} find
 */
module.exports = function (secret, ttl, find) {

  if(!secret) throw new Error('"secret" required');

  //defaults
  var ttl = ttl || 60*60*24 // a day
    , find = find || function (req) { return req.param('sr') || req.header('X-sr'); };

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
