/**
 * @fileoverview Implements the OAuth PKCE code flow for CLI Node.js desktop
 * app: https://datatracker.ietf.org/doc/html/rfc7636
 *
 * Usage:
 * const client = new OAuthClientServer(
 *     {
 *       clientId: 'CLIENT_ID',
 *       clientSecret: 'CLIENT_SECRET',
 *       authUri: 'AUTHORIZATION_URL',
 *       tokenUri: 'TOKEN_EXCHANGE_URL',
 *       revokeUri: 'TOKEN_REVOCATION_URL',
 *       logoutUri: 'LOGOUT_URL',
 *       successUri: 'REDIRECT_URL_AFTER_SIGN_IN'
 *     });
 * // Optional space delimited scopes string. If not provided, openid is used.
 * const oauthResponse = await client.authorize(scopes);
 * // To end early:
 * // client.close();
 *
 * // Refresh token functionality.
 * const oauthResponse = await client.refresh(refreshToken);
 *
 * // Revoke tokens functionality.
 * await client.revoke(refreshToken, 'refresh_token');
 *
 * // Revoke refresh token and generate logout URL.
 * const logoutUrl = await client.revokeAndGetLogoutUrl(refreshToken);
 *
 * The authorize() API works as follows:
 * - A local server is started with 2 endpoints /auth and /callback.
 * - A browser is opened and redirected to /auth endpoint.
 * - On /auth, state and codeVerifier are provisioned and stored locally,
 *   keyed by state.
 * - Session cookie session_state (httpOnly) set with the state value.
 * - 302 Redirect to authorization URL with query string populated for PKCE
 *   flow (using hashed code verifier). The redirect_uri is set to /callback.
 * - On IdP sign-in, IdP will redirect back to /callback with code+state in
 *   query string.
 * - /callback will match state in session cookie and lookup unhashed code
 *   verifier. It will then send request to exchange code + code_verifier for
 *   the token response.
 * - On successful exchange, a redirect to successUri is performed.
 * - The server is closed.
 *
 * The utility also provides functionality to exchange refresh tokens for
 * ID tokens, revoke OAuth tokens and generate logout URLs.
 */

const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const fetch = require('node-fetch');
const open = require('open');
// The host for the local server.
const HOST = 'localhost';
// The default port for the local server.
const PORT = 5555;
// Default OAuth scope.
const DEFAULT_SCOPE = 'openid';
// Length of characters in the state field.
const STATE_LENGTH = 20;
// Length of characters in the code verifier.
// Recommended to be between 43 and 128 chars.
const CODE_VERIFIER_LENGTH = 80;
// OAuth scope separator.
const SCOPE_SEPARATOR = ' ';

/**
 * Generates a random string of the specified length, optionally using the
 * specified alphabet.
 *
 * @param {number} length The length of the string to generate.
 * @param {string} charSet The optional char set to use.
 * @return {string} A random string of the provided length.
 */
function generateRandomString(length, charSet) {
  const chars = [];
  const allowedChars = charSet || 'abcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    chars.push(
        allowedChars.charAt(Math.floor(Math.random() * allowedChars.length))
    );
  }
  return chars.join('');
}

/**
 * Defines a utility to launch a local server to handle OAuth handshake
 * via PKCE. The client ID/secret and OAuth endpoints are configurable.
 * Additional OAuth functionality is also provided to exchange refresh tokens
 * for ID tokens, revoke tokens and generate logout URLs.
 */
class OAuthClientServer {
  /**
   * Initializes an OAuthClientServer instance.
   * @param {*} config The OAuth client configuration.
   */
  constructor(config) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.authUri = config.authUri;
    this.tokenUri = config.tokenUri;
    this.revokeUri = config.revokeUri;
    this.logoutUri = config.logoutUri;
    this.successUri = config.successUri;

    // Initialize with default scope.
    this.scopes = DEFAULT_SCOPE;

    this.server = null;
    this.serverAddress = null;
    this.sessionStore = {};
    this.app = express();
    this.app.use(cookieParser());
  }

  /**
   * Revokes the refresh token and returns the sign out link for the current
   * session.
   * https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
   * @param {string} refreshToken The OAuth refresh token.
   * @return {Promise<string>} A promise that resolves with the signout URL.
   */
  async revokeAndGetLogoutUrl(refreshToken) {
    // An ID token is needed for signout.
    const resp = await this.refresh(refreshToken);
    await this.revoke(refreshToken, 'refresh_token');
    return `${this.logoutUri}?id_token_hint=${resp.id_token}`;
  }

  /**
   * Initializes all the server endpoints and their logic.
   * This includes the /auth and /callback endpoints.
   * @param {function(*)} resolve The success callback to call with the OAuth
   *     response on success.
   * @param {function(*)} reject The error callback to call when the
   *     authorization fails.
   */
  init(resolve, reject) {
    this.app.get('/auth', (req, res) => {
      // Between 43 and 128 chars.
      const alphabet = 'abcdefghijklmnopqrstuvwxyz';
      const charSet = alphabet.toLowerCase() +
          alphabet.toUpperCase() + '0123456789' + '-._~';
      const codeVerifier = generateRandomString(CODE_VERIFIER_LENGTH, charSet);
      // BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).
      const codeChallenge = crypto.createHash('sha256')
          .update(codeVerifier)
          .digest('base64')
          // web-safe-base64.
          .replace(/\//g, '_').replace(/\+/g, '-')
          // Remove trailing equals.
          .replace(/=*$/, '');
      const state = generateRandomString(STATE_LENGTH);
      // Save code verifier keyed by state in session store.
      this.sessionStore[state] = codeVerifier;
      const authUri = this.authUri +
          `?client_id=${encodeURIComponent(this.clientId)}` +
          `&redirect_uri=` +
          `${encodeURIComponent(`${this.serverAddress}/callback`)}` +
          `&response_type=code` +
          `&scope=${encodeURIComponent(this.scopes)}` +
          `&code_challenge=${encodeURIComponent(codeChallenge)}` +
          `&code_challenge_method=S256` +
          '&prompt=login' +
          `&state=${encodeURIComponent(state)}`;
      // Redirect to the authorization URL after setting sesssions state cookie.
      res.cookie('session_state', state, {httpOnly: true});
      res.redirect(302, authUri);
    });

    this.app.get('/callback', async (req, res) => {
      const state = req.cookies['session_state'];
      const code = req.query.code;
      const actualState = req.query.state;
      if (actualState &&
          code &&
          state === actualState &&
          (typeof this.sessionStore[actualState] !== 'undefined')) {
        const codeVerifier = this.sessionStore[actualState];
        delete this.sessionStore[actualState];
        try {
          const response = await fetch(this.tokenUri, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: `grant_type=authorization_code` +
              `&client_id=${encodeURIComponent(this.clientId)}` +
              (this.clientSecret ?
               `&client_secret=${encodeURIComponent(this.clientSecret)}` :
               '') +
              `&code=${encodeURIComponent(code)}` +
              `&code_verifier=${encodeURIComponent(codeVerifier)}` +
              `&redirect_uri=` +
              `${encodeURIComponent(this.serverAddress + '/callback')}`,
          });
          const json = await response.json();
          if (response.status === 200) {
            res.redirect(this.successUri);
            resolve(json);
          } else {
            res.status(response.status);
            res.send(json.error);
            reject(new Error(json.error));
          }
        } catch (error) {
          res.status(500);
          res.send(error.message);
          reject(error);
        }
      } else {
        res.status(400);
        res.send('Invalid IdP response');
        reject(new Error('Invalid IdP response'));
      }
      // Close the local server used for authorization.
      this.close();
    });
  }

  /**
   * Revokes the provided token.
   * @param {string} token The OAuth token to revoke.
   * @param {string} tokenType The OAuth token type.
   * @return {Promise<void>} A promise that resolves on revocation completion.
   */
  async revoke(token, tokenType) {
    const fetchOptions = {
      method: 'POST',
      body: `token=${encodeURIComponent(token)}` +
          `&token_type_hint=${encodeURIComponent(tokenType)}` +
          `&client_id=${encodeURIComponent(this.clientId)}` +
          (this.clientSecret ?
           `&client_secret=${encodeURIComponent(this.clientSecret)}` : ''),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    };
    const res = await fetch(this.revokeUri, fetchOptions);
    if (res.status !== 200) {
      const json = await res.json();
      throw new Error(json.error_description || json.error || 'Unknown Error');
    }
  }

  /**
   * Refreshes the provided refresh token and resolves with the refreshed
   * tokens.
   * @param {string} refreshToken The OAuth refresh token.
   * @return {Promise<*>} A promise that resolves with the OAuth response.
   */
  async refresh(refreshToken) {
    const res = await fetch(this.tokenUri, {
        method: 'POST',
        body: `grant_type=refresh_token` +
            `&refresh_token=${encodeURIComponent(refreshToken)}` +
            `&client_id=${encodeURIComponent(this.clientId)}` +
            (this.clientSecret ?
             `&client_secret=${encodeURIComponent(this.clientSecret)}` : ''),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      });
    const json = await res.json();
    if (res.status !== 200) {
      throw new Error(json.error_description || json.error || 'Unknown Error');
    }
    return json;
  }

  /**
   * Starts the local server and the OAuth handshake.
   * @param {string=} scopes The optional space-delimited list of scopes.
   * @param {number=} port The port number to use. A default one is used when
   *     unspecified.
   * @return {Promise<*>} A promise that resolves with the OAuth response.
   */
  authorize(scopes, port=PORT) {
    // Only allow one authorization flow at a time.
    if (this.server) {
      return Promise.reject(new Error(
          'Pending authorization flow. Close existing session to rerun.'))
    }
    // openid is required for the ID token to be returned.
    this.scopes = scopes ?
        `${scopes}${SCOPE_SEPARATOR}${DEFAULT_SCOPE}` :
        DEFAULT_SCOPE;
    return new Promise((resolve, reject) => {
      this.init(resolve, reject);
      this.server = this.app.listen(port, HOST, () => {
        this.serverAddress = `http://${HOST}:${this.server.address().port}`;
        console.log('Redirecting to authorization URL');
        // Open the start url in the default browser.
        open(`${this.serverAddress}/auth`);
      });
    });
  }

  /**
   * Closes the local server used for PKCE flow.
   */
  close() {
    // Close server if open.
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }
}

// Keep things simple for now and use commonjs.
exports.OAuthClientServer = OAuthClientServer;