/**
 * @fileoverview Provides the main entry point for login and starting the
 * metadata server for workforce pool SDK testing.
 */

const express = require('express');
const keytar = require('keytar');
const {OAuthClientServer} = require('./pkce');
const oauthConfigJson = require('../oauth-config.json');
const app = express();
const cors = require('cors');
const axios = require('axios');
// The host for the local server.
const HOST = 'localhost';
// The port for the local server.
const PORT = 5000;
// The identifier used to key the keytar-stored refresh token.
const APP_ID = 'WorkforcePoolTesting';

// cors is needed for chatgpt to find the manifest file hosted by this server.
const corsOptions = {
  origin: 'https://chat.openai.com',
}
app.use(cors(corsOptions));

// Serve static files from the public directory. /.well-known/ai-plugin.json & /openapi.yaml
app.use(express.static('public'));


/**
 * Starts the metadata server using the provide OAuth client.
 * @param {OAuthClientServer} client The client instance used for token
 *     retrieval and revocation.
 */
function startMetadataServer(client) {
  // Start the server and log all the available endpoints.
  const server = app.listen(PORT, HOST, () => {
    const serverAddress = `http://${HOST}:${server.address().port}`;
    console.log(`Starting metadata server ${serverAddress}`);
    console.log(
      `Get token endpoint: http://${HOST}:${server.address().port}/token`);
    console.log(
      `Signout endpoint: http://${HOST}:${server.address().port}/logout`);
  });

/**
 * GET /token
 * Returns a new OIDC ID token using the stored refresh token.
 *
 * @param {Object} res The Express response object.
 * @returns {Object} The response object containing the new ID token or an error message.
 * @throws {Error} If there is no stored refresh token or if the refresh token is invalid.
 */
  app.get('/token', async (_, res) => {
    const refreshToken = await keytar.getPassword(
        APP_ID, 'RefreshToken');
    if (refreshToken) {
      try {
        const resp = await client.refresh(refreshToken);
        // Save refresh token if returned.
        if (resp.refresh_token) {
          await keytar.setPassword(
            APP_ID, 'RefreshToken', resp.refresh_token);
        }
        res.status(200);
        res.send(resp.id_token);
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'No session detected. Please login first.' });
    }
  });

  /**
   * GET /idptoken
   * Returns a new OIDC ID token using the stored refresh token.
   *
   * @param {Object} res The Express response object.
   * @returns {Object} The response object containing the new ID token or an error message.
   * @throws {Error} If there is no stored refresh token or if the refresh token is invalid.
   */
  app.get('/idptoken', async (_, res) => {
    const refreshToken = await keytar.getPassword(
        APP_ID, 'RefreshToken');
    if (refreshToken) {
      try {
        const resp = await client.refresh(refreshToken);
        // Save refresh token if returned.
        if (resp.refresh_token) {
          await keytar.setPassword(
            APP_ID, 'RefreshToken', resp.refresh_token);
        }
        res.status(200).json({ id_token: resp.id_token });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res.status(400).json({ error: 'No session detected. Please login first.' });
    }
  });



  /**
   * Exchanges an input token for a GCP access token using the
   * `securitytoken.googleapis.com/token` endpoint.
   *
   * @param {Object} req - The request object.
   * @param {Object} req.query - The query object containing the `input_token` parameter.
   * @param {string} req.query.input_token - The input token to exchange for a GCP access token.
   * @param {Object} res - The response object.
   * @returns {Promise<void>} - A Promise that resolves when the response is sent.
   */
  app.get('/gcpaccesstoken', async (req, res) => {
    const inputToken = req.query.input_token;
    if (!inputToken) {
      res.status(400).json({ error: 'Missing input_token parameter.' });
      return;
    }

    const audience = '//iam.googleapis.com/locations/global/workforcePools/wf-pools-testing-sdk14/providers/okta-oidc-provider';
    const grantType = 'urn:ietf:params:oauth:grant-type:token-exchange';
    const requestedTokenType = 'urn:ietf:params:oauth:token-type:access_token';
    const scope = 'https://www.googleapis.com/auth/cloud-platform';
    const subjectTokenType = 'urn:ietf:params:oauth:token-type:id_token';
    const subjectToken = inputToken;
    const options = { userProject: '307586025878' };

    try {
      const response = await axios.post(
        'https://sts.googleapis.com/v1/token',
        {
          audience,
          grant_type: grantType,
          requested_token_type: requestedTokenType,
          scope,
          subject_token_type: subjectTokenType,
          subject_token: subjectToken,
          options: JSON.stringify(options),
        },
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );
      const accessToken = response.data.access_token;
      res.status(200).json({ access_token: accessToken });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  /**
 * Retrieves a list of GCP projects using the `resourcemanager.googleapis.com/projects` API.
 *
 * @param {Object} req - The request object.
 * @param {Object} req.headers - The request headers containing the `Authorization` header with the input access token.
 * @param {string} req.headers.authorization - The `Authorization` header with the input access token.
 * @param {Object} res - The response object.
 * @returns {Promise<void>} - A Promise that resolves when the response is sent.
 */
app.get('/gcpprojects', async (req, res) => {
  const accessToken = req.headers.authorization.split(' ')[1];
  if (!accessToken) {
    res.status(401).json({ error: 'Missing access token.' });
    return;
  }

  try {
    const response = await axios.get(
      'https://cloudresourcemanager.googleapis.com/v3/projects',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );
    const projects = response.data.projects.map((project) => project.projectId);
    res.status(200).json({ projects });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
  // Expose an endpoint to logout the current session.
  // This will revoke and clear the stored refresh token and also
  // redirect the browser to the logout URL logging the user out
  // from the browser too.
  // On success, the server is also shutdown.
  app.get('/logout', async (req, res) => {
    try {
      const refreshToken = await keytar.getPassword(
          APP_ID, 'RefreshToken');
      await keytar.deletePassword(APP_ID, 'RefreshToken');
      res.redirect(await client.revokeAndGetLogoutUrl(refreshToken));
      server.close();
      process.exit(0);
    } catch (error) {
      res.status(500);
      res.send(error.message);
    }
  });
}

/**
 * Starts the metadata server for token retrieval and sign-out
 * after a session is established.
 * If a session is not available, triggers the authorization flow
 * first before starting the metadata server.
 */
async function main() {
  const client = new OAuthClientServer(oauthConfigJson);

  // Login everytime the server is started.
  try {
    await keytar.deletePassword(APP_ID, 'RefreshToken');
    // "offline_access" is needed since we need to get and store a refresh
    // token.
    // "email" is needed so the JWT will also contain a user friendly
    // email identifier.
    const jsonResponse = await client.authorize('offline_access email');
    // Save new refresh token if returned.
    if (jsonResponse.refresh_token) {
      await keytar.setPassword(
          APP_ID, 'RefreshToken', jsonResponse.refresh_token);
    }
    // Start metadata server.
    startMetadataServer(client);
  } catch (error) {
    // On error print the expected output.
    console.log(error);
  }
  
  // // Check if refresh token is already stored to avoid re-login everytime.
  // const refreshToken = await keytar.getPassword(
  //     APP_ID, 'RefreshToken');
  // if (refreshToken) {
  //   console.log('Existing session detected.');
  //   startMetadataServer(client);
  // } else {
  //   console.log('No existing session detected.');
  //   try {
  //     // "offline_access" is needed since we need to get and store a refresh
  //     // token.
  //     // "email" is needed so the JWT will also contain a user friendly
  //     // email identifier.
  //     const jsonResponse = await client.authorize('offline_access email');
  //     // Save new refresh token if returned.
  //     if (jsonResponse.refresh_token) {
  //       await keytar.setPassword(
  //           APP_ID, 'RefreshToken', jsonResponse.refresh_token);
  //     }
  //     // Start metadata server.
  //     startMetadataServer(client);
  //   } catch (error) {
  //     // On error print the expected output.
  //     console.log(error);
  //   }
  // }
}

main();
