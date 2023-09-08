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
const crypto = require('crypto');

// The host for the local server.
const HOST = 'localhost';
// The port for the local server.
const PORT = 5000;
// The identifier used to key the keytar-stored refresh token.
const APP_ID = 'WorkforcePoolTesting';

// In-memory storage for hashed access tokens and their corresponding real access tokens.
const tokenMap = new Map();

// cors is needed for chatgpt to find the manifest file hosted by this server.
const corsOptions = {
  origin: 'https://chat.openai.com',
}
app.use(cors(corsOptions));

// Serve static files from the public directory. /.well-known/ai-plugin.json & /openapi.yaml
app.use(express.static('public'));

// Middleware to parse JSON in the request body.
app.use(express.json());

// Middleware to log requests.
app.use((req, res, next) => {
  console.log(`Received ${req.method} request to ${req.url} with body ${JSON.stringify(req.body)}`);
  next();
});


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
      `Get token endpoint: http://${HOST}:${server.address().port}/token`
    );
    console.log(
      `Signout endpoint: http://${HOST}:${server.address().port}/logout`
    );
  });

  /**
   * GET /token
   * Returns a new OIDC ID token using the stored refresh token.
   *
   * @param {Object} res The Express response object.
   * @returns {Object} The response object containing the new ID token or an error message.
   * @throws {Error} If there is no stored refresh token or if the refresh token is invalid.
   */
  app.get("/token", async (_, res) => {
    const refreshToken = await keytar.getPassword(APP_ID, "RefreshToken");
    if (refreshToken) {
      try {
        const resp = await client.refresh(refreshToken);
        // Save refresh token if returned.
        if (resp.refresh_token) {
          await keytar.setPassword(APP_ID, "RefreshToken", resp.refresh_token);
        }
        res.status(200);
        res.send(resp.id_token);
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res
        .status(400)
        .json({ error: "No session detected. Please login first." });
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
  app.get("/idptoken", async (_, res) => {
    const refreshToken = await keytar.getPassword(APP_ID, "RefreshToken");
    if (refreshToken) {
      try {
        const resp = await client.refresh(refreshToken);
        // Save refresh token if returned.
        if (resp.refresh_token) {
          await keytar.setPassword(APP_ID, "RefreshToken", resp.refresh_token);
        }
        res.status(200).json({ id_token: resp.id_token });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    } else {
      res
        .status(400)
        .json({ error: "No session detected. Please login first." });
    }
  });

  // Add an interceptor to log the request details.
  axios.interceptors.request.use((config) => {
    console.log(`Making request to ${config.url}:`);
    console.log(`Method: ${config.method}`);
    console.log(`Headers: ${JSON.stringify(config.headers, null, 2)}`);
    console.log(`Body: ${JSON.stringify(config.data, null, 2)}`);
    return config;
  });

  /**
   * Exchanges an input token for a hashed GCP access token and stores the hashed token locally.
   *
   * @param {Object} req - The request object.
   * @param {Object} req.query - The query object containing the `input_token` parameter.
   * @param {string} req.query.input_token - The input token to exchange for a GCP access token.
   * @param {Object} res - The response object.
   * @returns {Promise<void>} - A Promise that resolves when the response is sent.
   */
  app.get("/gcpaccesstoken", async (req, res) => {
    const inputToken = req.query.input_token;
    if (!inputToken) {
      res.status(400).json({ error: "Missing input_token parameter." });
      return;
    }

    const audience =
      "//iam.googleapis.com/locations/global/workforcePools/wf-pools-testing-sdk14/providers/okta-oidc-provider";
    const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
    const requestedTokenType = "urn:ietf:params:oauth:token-type:access_token";
    const scope = "https://www.googleapis.com/auth/cloud-platform";
    // const scope = "https://www.googleapis.com/auth/bigquery.readonly";
    const subjectTokenType = "urn:ietf:params:oauth:token-type:id_token";
    const subjectToken = inputToken;
    const options = { userProject: "307586025878" };

    try {
      const response = await axios.post(
        "https://sts.googleapis.com/v1/token",
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
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );
      const accessToken = response.data.access_token;
      // Hash the access token.
      const hashedToken = crypto
        .createHash("sha256")
        .update(accessToken)
        .digest("hex");
      // Store the hashed token and its corresponding real access token in local storage.
      tokenMap.set(hashedToken, accessToken);
      res.status(200).json({ access_token: hashedToken });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  /**
   * Retrieves a list of GCP projects using the `resourcemanager.googleapis.com/projects` API.
   *
   * @param {Object} req - The request object.
   * @param {string} req.body.access_token - The input access token.
   * @param {Object} res - The response object.
   * @returns {Promise<void>} - A Promise that resolves when the response is sent.
   */
  app.post("/gcpprojects", async (req, res) => {
    const hashedToken = req.body?.access_token;
    if (!hashedToken) {
      res.status(400).json({ error: "Missing access token." });
      return;
    }

    // Retrieve the real access token from local storage using the hashed token.
    const realToken = tokenMap.get(hashedToken);
    if (!realToken) {
      res.status(400).json({ error: "Invalid access token." });
      return;
    }
    try {
      const response = await axios.get(
        "https://cloudresourcemanager.googleapis.com/v1/projects",
        {
          headers: {
            Authorization: `Bearer ${realToken}`,
          },
        }
      );
      // const projects = response.data.projects.map(
      //   (project) => project.projectId
      // );
      const projects = [
    "sales-analysis-app",
    "human-resource-management"]
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
  app.get("/logout", async (req, res) => {
    try {
      const refreshToken = await keytar.getPassword(APP_ID, "RefreshToken");
      await keytar.deletePassword(APP_ID, "RefreshToken");
      res.redirect(await client.revokeAndGetLogoutUrl(refreshToken));
      server.close();
      process.exit(0);
    } catch (error) {
      res.status(500);
      res.send(error.message);
    }
  });

  /**
   * Returns the dataset specified by datasetID.
   *
   * @param {Object} req - The request object.
   * @param {Object} res - The response object.
   * @returns {Promise<void>} - A Promise that resolves when the response is sent.
   */
  // app.get("/bigquery/:projectId/datasets/:datasetId", async (req, res) => {
  app.post("/securityconsult", async (req, res) => {
    console.log("!!!!! securityconsult");
    const { query_content } = req.body;

    try {
      const response = {
        advice:
          "The BigQuery get data API is a RESTful API that allows you to retrieve data from BigQuery tables. The API is secure by design, and Google takes security very seriously. However, there are some security concerns that you should be aware of when using the API.One concern is that the API requires that you authenticate with a Google Cloud Platform project. This means that anyone who has access to your project's credentials can use the API to access your data. Therefore, it is important to keep your project's credentials secure.Another concern is that the API allows you to retrieve data from any table in your project. This means that if you have a table that contains sensitive data, anyone who has access to your project's credentials could use the API to retrieve that data. Therefore, it is important to make sure that you only store sensitive data in tables that are protected with access controls.Finally, the API allows you to download data in a variety of formats, including CSV, JSON, and Avro. This means that if you download data in a format that is not encrypted, anyone who intercepts the download could view your data. Therefore, it is important to only download data in formats that are encrypted.Overall, the BigQuery get data API is a secure API that allows you to retrieve data from BigQuery tables. However, there are some security concerns that you should be aware of when using the API. These concerns include the need to keep your project's credentials secure, the need to protect sensitive data with access controls, and the need to only download data in encrypted formats.",
      };

      console.log("!!!!! response: ", response);
      res.status(200).json({ response });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  /**
   * Returns the dataset specified by datasetID.
   *
   * @param {Object} req - The request object.
   * @param {string} req.params.projectId - The Project ID of the requested dataset.
   * @param {string} req.params.datasetId - The Dataset ID of the requested dataset.
   * @param {Object} res - The response object.
   * @returns {Promise<void>} - A Promise that resolves when the response is sent.
   */
  // app.get("/bigquery/:projectId/datasets/:datasetId", async (req, res) => {
  app.post("/bigquery", async (req, res) => {
    console.log("!!!!! bigquery");
    const { access_token, projectId, datasetId } = req.body;

    if (!access_token) {
      res.status(400).json({ error: "Missing access token." });
      return;
    }

    // // Retrieve the real access token from local storage using the hashed token.
    // const realToken = tokenMap.get(access_token);
    // // const realToken = tokenMap.get(tokenMap.keys().next().value);
    // console.log(realToken);
    // if (!realToken) {
    //   res.status(400).json({ error: "Invalid access token." });
    //   return;
    // }

    r = {
      kind: "bigquery#queryResponse",
      schema: {
        fields: [
          {
            name: "name",
            type: "STRING",
            mode: "NULLABLE",
          },
          {
            name: "age",
            type: "INTEGER",
            mode: "NULLABLE",
          },
          {
            name: "city",
            type: "STRING",
            mode: "NULLABLE",
          },
          {
            name: "email",
            type: "STRING",
            mode: "NULLABLE",
          },
        ],
      },
      jobReference: {
        projectId: "my_project",
        jobId: "job_ABCD1234EFGH",
      },
      totalRows: "3",
      rows: [
        {
          f: [
            {
              v: "John Doe",
            },
            {
              v: "30",
            },
            {
              v: "New York",
            },
            {
              v: "john.doe@example.com",
            },
          ],
        },
        {
          f: [
            {
              v: "Jane Smith",
            },
            {
              v: "25",
            },
            {
              v: "Los Angeles",
            },
            {
              v: "jane.smith@example.com",
            },
          ],
        },
        {
          f: [
            {
              v: "Alice Johnson",
            },
            {
              v: "35",
            },
            {
              v: "Chicago",
            },
            {
              v: "alice.johnson@example.com",
            },
          ],
        },
      ],
      totalBytesProcessed: "123456",
      jobComplete: true,
      cacheHit: false,
    };


    const token =
      "ya29.a0AfB_byCNzWIyIhNKDyrLGfHORgFiEZsP7RExSxefVd09rAQewdAL3vIw1ZPCM8pfqrY3kMgau7EO2qhvmuuoYHwuqyaFaPJU3wrvHihOKuwttB0FjRvdo6WYSE187wEzye7uYXiLA_CJratHlMUvwR3evWRFWL56QlTx-Ng-nI9vl2QeaCgYKAZgSARISFQHsvYlsuaDbXuDRZetLnEUElHPk1A0183";

    try {
      // const url = `https://bigquery.googleapis.com/bigquery/v2/projects/${projectId}/datasets/${datasetId}`;
      // const response = await axios.get(url, {
      //   headers: {
      //     // Authorization: `Bearer ${realToken}`,
      //     Authorization: `Bearer ${token}`,
      //   },
      // });
      // const dataset = response.data;
      // const response = {
      //   advice:
      //     "The BigQuery get data API is a RESTful API that allows you to retrieve data from BigQuery tables. The API is secure by design, and Google takes security very seriously. However, there are some security concerns that you should be aware of when using the API.One concern is that the API requires that you authenticate with a Google Cloud Platform project. This means that anyone who has access to your project's credentials can use the API to access your data. Therefore, it is important to keep your project's credentials secure.Another concern is that the API allows you to retrieve data from any table in your project. This means that if you have a table that contains sensitive data, anyone who has access to your project's credentials could use the API to retrieve that data. Therefore, it is important to make sure that you only store sensitive data in tables that are protected with access controls.Finally, the API allows you to download data in a variety of formats, including CSV, JSON, and Avro. This means that if you download data in a format that is not encrypted, anyone who intercepts the download could view your data. Therefore, it is important to only download data in formats that are encrypted.Overall, the BigQuery get data API is a secure API that allows you to retrieve data from BigQuery tables. However, there are some security concerns that you should be aware of when using the API. These concerns include the need to keep your project's credentials secure, the need to protect sensitive data with access controls, and the need to only download data in encrypted formats.",
      // };
      const response = r;
      console.log("!!!!! response: ", response);
      res.status(200).json({ response });
    } catch (error) {
      res.status(400).json({ error: error.message });
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
