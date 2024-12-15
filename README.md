# AWS Send Webhook

A GitHub Action to securely send a webhook to an AWS webhook handler, leveraging a secret token stored in AWS Secrets Manager. This Action uses GitHub's OIDC token to assume an AWS IAM role, fetches the secret, and sends the webhook request with customizable headers and payload. The secret is also used to generate and the X-Hub-Signature-256 header, giving the ability to ensuring the authenticity of the webhook in the webhook handler.

---

## Features

- Assumes an AWS IAM role via GitHub's OIDC to securely access AWS Secrets Manager.
- Retrieves a secret (e.g., token) from AWS Secrets Manager.
- Uses the secret to compute the X-Hub-Signature-256 header for secure webhook handling.
- Sends an HTTP POST request with the retrieved secret as part of the headers.
- Supports custom headers and content types for flexibility.
- Fully parameterized via inputs for dynamic use in workflows.

---

## Inputs

| Name                 | Description                                                                                   | Required | Default             |
|----------------------|-----------------------------------------------------------------------------------------------|----------|---------------------|
| `webhook_url`        | The URL to which the webhook will be sent.                                                    | `true`   |                     |
| `aws_region`         | The AWS region where the secret is stored.                                                    | `true`   |                     |
| `aws_role_to_assume` | The AWS IAM role to assume for accessing Secrets Manager.                                     | `true`   |                     |
| `audience`           | The audience value to be included in the OIDC token request URL, if applicable.               | `false`  | `sts.amazonaws.com` |
| `secret_name`        | The name of the secret in AWS Secrets Manager to fetch (e.g., a token).                       | `true`   |                     |
| `content_type`       | Content-Type header for the request (e.g., `application/json`).                               | `false`  | `application/json`  |
| `headers`            | Optional JSON object of additional headers to include in the request.                         | `false`  |                     |
| `payload`            | The JSON payload to send in the webhook request.                                              | `true`   |                     |

---

## Usage

Here is an example of how to use this GitHub Action in your workflow:

```yaml
name: Send Webhook

on:
  push:
    branches:
      - main

jobs:
  send-webhook:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Send Webhook to AWS
        uses: your-repo/aws-send-webhook-action@v1
        with:
          webhook_url: ${{ secrets.WEBHOOK_URL }}
          aws_region: us-east-1
          aws_role_to_assume: arn:aws:iam::123456789012:role/GitHubActionsSecretManagerRole
          secret_name: my-secret-token
          content_type: application/json
          headers: '{"X-GitHub-Event": "push"}'
          payload: '{"message": "Hello, world!"}'
```

---

## How It Works

1. **Assume AWS Role**:  
   The action uses the GitHub OIDC token to assume the specified AWS IAM role (`aws_role_to_assume`). This provides temporary credentials to access AWS services securely.

2. **Fetch Secret from AWS Secrets Manager**:  
   The action retrieves the secret (`secret_name`) from AWS Secrets Manager using the temporary credentials. This secret is used as part of the webhook request, typically for authentication or signing.
   **Important**: The secret must contain a key named `Token` under which the token value is stored. Ensure that the secret follows this structure.

3. **Send Webhook**:  
   The action sends an HTTP POST request to the specified `webhook_url` using the provided `payload`. The secret is included in the headers, and additional custom headers can be passed as a JSON object.

---

## Inputs Explained

### `webhook_url`
- The endpoint URL for the webhook.  
- Example: `https://api.example.com/webhook`.

### `aws_region`
- The AWS region where your secret is stored.  
- Example: `us-east-1`.

### `aws_role_to_assume`
- The ARN of the AWS IAM role the action will assume to access Secrets Manager.  
- Example: `arn:aws:iam::123456789012:role/GitHubActionsSecretManagerRole`.

### `secret_name`
- The name of the secret stored in AWS Secrets Manager.  
- Note: The secret must contain a key named `Token`.
- Example: `my-secret-token`.

### `content_type`
- Specifies the `Content-Type` header for the webhook request.  
- Default: `application/json`.  
- Example: `application/x-www-form-urlencoded`.

### `headers`
- Additional headers to include in the webhook request. Must be a valid JSON object.  
- Example: `{"X-Custom-Header": "value"}`.

### `payload`
- The JSON-formatted body of the webhook request.  
- Example: `{"message": "Hello, world!"}`.

---

## Security Best Practices

- Use the least privilege principle for the IAM role (`aws_role_to_assume`).  
- Ensure secrets in AWS Secrets Manager are properly encrypted and access-controlled.  
- Do not hardcode sensitive values in workflows; use GitHub Secrets instead.  

---

## Troubleshooting

- **Error: Unable to assume role**:  
  Ensure the GitHub OIDC provider is configured correctly in AWS and the IAM role trust policy allows the workflow to assume the role.

- **Error: Secret not found**:  
  Double-check the `secret_name` and ensure the role has the necessary permissions (`secretsmanager:GetSecretValue`) to retrieve the secret.

- **Webhook not sent**:  
  Verify the `webhook_url`, `payload`, and headers are correct. Check the server logs for more details.

