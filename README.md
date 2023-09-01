# Testing Workforce Pools with Cloud SDKs

This repo provides tools to facilitate testing workforce pools
with the Cloud SDKs (Google Cloud Auth Libraries and CLIs, e.g. gcloud).

It provides an easy mechanism to sign in with a third party OIDC provider
and launch a metadata server compatible with Identity Pool credentials
which support URL-sourced credentials as defined in go/guac-3pi.

## Contributing

If you want to submit CLs to the repo through gerrit, you will want to clone
the repo with the ‘commit message hook’ installed:

```bash
git clone sso://team/byoid-client-eng/workforce-pool-sdk-testing && (cd workforce-pool-sdk-testing && f=`git rev-parse --git-dir`/hooks/commit-msg ; mkdir -p $(dirname $f) ; curl -Lo $f https://gerrit-review.googlesource.com/tools/hooks/commit-msg ; chmod +x $f)
```

To begin code review:

```bash
# If this is the first commit of the CL, do:
git commit -am "Commit message"

# If you are responding to comments, do:
git commit --amend

# To upload the changes to gerrit:
git push origin HEAD:refs/for/master
```

Note you need to be a member of `mdb/byoid-client-eng` in order to contribute
to this repo.

## Prerequisites

Configure an OIDC provider with Okta using authorization code with
[PKCE grant-type](https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main/).
When configuring the OAuth client, use `http://localhost:5555/callback` as
an authorized redirect URI.

You will also need to make sure you create an OIDC provider in your workforce
pool.

For more on configuring workforce pools and their providers, refer to
[Workforce pool testing](https://docs.google.com/document/d/1-vCqjrj3KMm7YQqNnKMj5mO3yzufcns-iX9WXRbNvAk/)
instructions.

You can do so with [gcloud](https://cloud.google.com/sdk/):

```bash
gcloud iam workforce-pools providers create-oidc $PROVIDER_ID \
  --location global \
  --workforce-pool $WORKFORCE_POOL_ID \
  --issuer-uri 'https://$OKTA_DOMAIN/oauth2/default' \
  --client-id $OKTA_CLIENT_ID \
  --attribute-mapping "google.subject=assertion.email" \
  --billing-project $WORKFORCE_POOL_BILLING_PROJECT_ID
```

You will need to ensure the principal has access to the GCP resources used for
testing:

```bash
gcloud organizations add-iam-policy-binding $ORG_ID \
  --member principal://iam.googleapis.com/locations/global/workforcePools/$WORKFORCE_POOL_ID/subject/$USER_SUBJECT \
  --role roles/storage.objectAdmin

gcloud organizations add-iam-policy-binding $ORG_ID \
  --member principal://iam.googleapis.com/locations/global/workforcePools/$WORKFORCE_POOL_ID/subject/$USER_SUBJECT \
  --role roles/iam.serviceAccountUser
```

Finally, you need to generate the configuration file needed to test with the
cloud SDKs.

```bash
gcloud iam workforce-pools create-cred-config \
  locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID \
  --credential-source-url http://localhost:5000/token \
  --workforce-pool-user-project $WORKFORCE_POOL_BILLING_PROJECT_NUMBER \
  --output-file workforce-config.json
```

This will generate the following JSON file `workforce-config.json`:

```javascript
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/locations/global/workforcePools/$WORKFORCE_POOL_ID/providers/$PROVIDER_ID",
  "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
  "token_url": "https://sts.googleapis.com/v1/token",
  "workforce_pool_user_project": "$WORKFORCE_POOL_BILLING_PROJECT_NUMBER",
  "credential_source": {
    "url": "http://localhost:5000/token"
  }
}
```

At the time of writing, the `gcloud iam workforce-pools create-cred-config`
command is not yet implemented. You can manually create it using the template
above and substituting your parameters.

Next you need to start the process to login to the IdP and start the local
metadata server.

## Login Script

Before you can use the script, you must have the following installed:

- Node.js (>= 14.0.0)
- npm (should be included with [Node.js](https://nodejs.org/en/download/))

The package dependencies also have to be installed by running the following in
the root folder: `npm install`

Make a copy of the file `./sample-oauth-config.json` and name the copy
`./oauth-config.json`. This file will not be checked in as it may
contain a client secret (Google PKCE uses a secret whereas Okta doesn't).

```
cp ./sample-oauth-config.json oauth-config.json
```

The file should be populated with all the relevant OAuth information:

```javascript
{
  "clientId": "$CLIENT_ID_GOES_HERE",
  "clientSecret": "$CLIENT_SECRET_GOES_HERE",
  "authUri": "https://accounts.google.com/o/oauth2/v2/auth",
  "tokenUri": "https://oauth2.googleapis.com/token",
  "revokeUri": "https://oauth2.googleapis.com/revoke",
  "logoutUri": "https://accounts.google.com/logout",
  "successUri": "https://developers.google.com/identity/protocols/oauth2/native-app"
}
```

The different OAuth URIs need to be substituted above.

The script uses the
[PKCE protocol](https://datatracker.ietf.org/doc/html/rfc7636) and can support
non-Google identities that adhere to the spec. For our testing, we will use an
Okta OIDC provider.

Start login and metadata server launch: `npm run start-login`

This will start a local server at port 5555 to handle the OAuth handshake.

When prompted, login using the Okta test account corresponding to the
authorized principal above.

On successful sign-in, the port 5555 server is closed and a local metadata
server is started at port 5000.

The script will store the OIDC refresh token using OS-specific secure storage,
e.g. Keychain in MacOS. So restarting the process should detect the existing
stored refresh token and skip the authorization flow.

To force logout and restart the authorization flow on the next run, visit the
logout URL hosted by the metadata server: `http://localhost:5000/logout`.

Login is only needed once. The underlying refresh token will be used to
silently generate new ID tokens for testing as long as the refresh token is
valid.
This is exposed via the `http://localhost:5000/token` endpoint.

After login, you can now start testing with SDKs.

## Start Testing

Note that this feature is still under development at the time of writing, and
custom builds of gcloud and the Auth libraries may be needed. Refer to
[go/workforce-sdk-testing] for more details.

After login, you can now start testing as follows:

With gcloud you can login with the same workforce credentials:

```bash
gcloud auth login --cred-file=/path/to/workforce-config.json \
  --project=$WORKFORCE_POOL_BILLING_PROJECT_ID
```

<pre>
# The output will have the form:
Authenticated with external account user credentials for: [principal://iam.googleapis.com/locations/global/workforcePools/wf-pools-testing-sdk/subject/tester@byoid.goog].
Your current project is [wf-pools-testing].  You can change this setting by running:
gcloud config set project PROJECT_ID
</pre>

You can list the current sessions and the corresponding principal should be
listed as active.

```bash
gcloud auth list
```

<pre>
# The output will have the form:
                        Credentialed Accounts
ACTIVE  ACCOUNT
*       principal://iam.googleapis.com/locations/global/workforcePools/wf-pools-testing-sdk/subject/tester@byoid.goog

To set the active account, run:
    $ gcloud config set account `ACCOUNT`
</pre>

You can make gcloud API calls authenticated with the workforce credentials:

```bash
gcloud iam service-accounts list
```

<pre>
# The output will have the form:
DISPLAY NAME                            EMAIL                                                                   DISABLED
Compute Engine default service account  307586025878-compute@developer.gserviceaccount.com                      False
...
</pre>

To test with client libraries, first export the `GOOGLE_APPLICATION_CREDENTIALS`
environment variable.

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/workforce-config.json
```

You can now run the sample program or script using the Auth library
to access a resource using ADC strategy.

```python
from google.cloud import storage

import google.auth

scopes=['https://www.googleapis.com/auth/cloud-platform']
credentials, _ = google.auth.default(scopes=scopes)

client = storage.Client(
    project='wf-pools-testing', credentials=credentials)
bucket = client.bucket('wf-waa-test-bucket')
blob = bucket.blob('test.txt')
# This should print out the content of the file.
print(blob.download_as_bytes().decode('utf-8'))
```
