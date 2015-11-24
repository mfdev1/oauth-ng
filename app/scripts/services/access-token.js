'use strict';

var accessTokenService = angular.module('oauth.accessToken', []);

accessTokenService.factory('AccessToken', ['Storage', '$rootScope', '$location', '$interval', '$log', '$base64', function(Storage, $rootScope, $location, $interval, $log, $base64){

  var service = {
    issuer: null, // TODO: need?
    clientId: null, // TODO: same
    token: null
  },
  oAuth2HashTokens = [ //per http://tools.ietf.org/html/rfc6749#section-4.2.2
    'access_token', 'id_token', 'token_type', 'expires_in', 'scope', 'state',
    'error','error_description'
  ];

  /**
   * Returns the access token.
   */
  service.get = function(){
    return this.token;
  };

  /**
   * Sets and returns the access token. It tries (in order) the following strategies:
   * - takes the token from the fragment URI
   * - takes the token from the sessionStorage
   */
  service.set = function(scope){
    // copy directive attributes
    this.issuer = scope.site;
    this.clientId = scope.clientId;

    this.setTokenFromString($location.hash());

    //If hash is present in URL always use it, cuz its coming from oAuth2 provider redirect
    if(null === service.token){
      setTokenFromSession();
    }

    return this.token;
  };

  /**
   * Delete the access token and remove the session.
   * @returns {null}
   */
  service.destroy = function(){
    Storage.delete('token');
    this.token = null;
    return this.token;
  };

  /**
   * Tells if the access token is expired.
   */
  service.expired = function(){
    return (this.token && this.token.expires_at && new Date(this.token.expires_at) < new Date());
  };

  /**
   * Get the access token from a string and save it
   * @param hash
   */
  service.setTokenFromString = function(hash){
    var params = getTokenFromString(hash);

    if (!params) {
      return; // TODO: Exception ?
    }

    var claims;
    if (params.id_token) {
      claims = validateIdToken(params.id_token);
    }

    if (!claims) {
      return; // TODO: Exception ?
    }

    removeFragment();
    setToken(params);

    service.token.idTokenClaims = claims;

    setExpiresAt();
    // We have to save it again to make sure expires_at is set
    //  and the expiry event is set up properly
    setToken(this.token);
    $rootScope.$broadcast('oauth:login', service.token);
  };

  /* * * * * * * * * *
   * PRIVATE METHODS *
   * * * * * * * * * */

  /**
   * Set the access token from the sessionStorage.
   */
  var setTokenFromSession = function(){
    var params = Storage.get('token');
    if (params) {
      setToken(params);
    }
  };

  /**
   * Set the access token.
   *
   * @param params
   * @returns {*|{}}
   */
  var setToken = function(params){
    service.token = service.token || {};      // init the token
    angular.extend(service.token, params);      // set the access token params
    setTokenInSession();                // save the token into the session
    setExpiresAtEvent();                // event to fire when the token expires

    return service.token;
  };

  /**
   * Parse the fragment URI and return an object
   * @param hash
   * @returns {{}}
   */
  var getTokenFromString = function(hash){
    var params = {},
        regex = /([^&=]+)=([^&]*)/g,
        m;

    while ((m = regex.exec(hash)) !== null) {
      params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
    }

    if(params.access_token || params.error){
      return params;
    }
  };

  /**
   * Save the access token into the session
   */
  var setTokenInSession = function(){
    Storage.set('token', service.token);
  };

  /**
   * Set the access token expiration date (useful for refresh logics)
   */
  var setExpiresAt = function(){
    if (!service.token) {
      return;
    }
    if(typeof(service.token.expires_in) !== 'undefined' && service.token.expires_in !== null) {
      var expires_at = new Date();
      expires_at.setSeconds(expires_at.getSeconds() + parseInt(service.token.expires_in)-60); // 60 seconds less to secure browser and response latency
      service.token.expires_at = expires_at;
    }
    else {
      service.token.expires_at = null;
    }
  };


  /**
   * Set the timeout at which the expired event is fired
   */
  var setExpiresAtEvent = function(){
    // Don't bother if there's no expires token
    if (typeof(service.token.expires_at) === 'undefined' || service.token.expires_at === null) {
      return;
    }
    var time = (new Date(service.token.expires_at))-(new Date());
    if(time && time > 0){
      $interval(function(){
        $rootScope.$broadcast('oauth:expired', service.token);
      }, time, 1);
    }
  };

  /**
   * Remove the oAuth2 pieces from the hash fragment
   */
  var removeFragment = function(){
    var curHash = $location.hash();
    angular.forEach(oAuth2HashTokens,function(hashKey){
      var re = new RegExp('&'+hashKey+'(=[^&]*)?|^'+hashKey+'(=[^&]*)?&?');
      curHash = curHash.replace(re,'');
    });

    $location.hash(curHash);
  };

  /**
   * validate id token
   * TODO: false or claims returnable like a PHP. I don't like
   * @param idToken
   * @param accessToken
   * @returns {boolean}
   */
  var validateIdToken = function(idToken, accessToken){
    var tokenParts = idToken.split('.');
    var claimsBase64 = padBase64(tokenParts[1]);
    var claimsJson = $base64.decode(claimsBase64);
    var claims = JSON.parse(claimsJson);
    var savedNonce = localStorage.getItem('nonce');

    if (claims.aud !== service.clientId) {
      $log.warn('Wrong audience: ' + claims.aud);
      return false;
    }

    if (service.issuer && claims.iss !== service.issuer) {
      $log.warn('Wrong issuer: ' + claims.iss);
      return false;
    }

    if (savedNonce && claims.nonce !== savedNonce) {
      $log.warn('Wrong nonce: ' + claims.nonce);
      return false;
    }

    //if (accessToken && !this.checkAtHash(accessToken, claims)) { // TODO: implement
    //  $log.warn('Wrong at_hash');
    //  return false;
    //}

    var now = Date.now();
    var issuedAtMSec = claims.iat * 1000;
    var expiresAtMSec = claims.exp * 1000;

    var tenMinutesInMsec = 1000 * 60 * 10;

    if (issuedAtMSec - tenMinutesInMsec >= now  || expiresAtMSec + tenMinutesInMsec <= now) {
      $log.warn('Token has been expired');
      $log.warn({
        now: now,
        issuedAtMSec: issuedAtMSec,
        expiresAtMSec: expiresAtMSec
      });
      return false;
    }

    //localStorage.setItem('id_token', idToken);
    //localStorage.setItem('id_token_claims_obj', claimsJson);
    //localStorage.setItem('id_token_expires_at', expiresAtMSec);
    //
    //if (this.validationHandler) {
    //  this.validationHandler(idToken)
    //}

    //return true;

    return claims;
  };

  var padBase64 = function (base64data) {
    while (base64data.length % 4 !== 0) {
      base64data += '=';
    }
    return base64data;
  };

  return service;

}]);
