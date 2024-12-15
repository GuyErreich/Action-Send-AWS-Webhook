#!/usr/local/bin/python


import argparse
import json
import requests
import logging
import hmac
import hashlib
import boto3
import os
import jwt
from botocore.config import Config

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# INFO: for debugging purposes
# def debug_oidc_token(token):
#     decoded = jwt.decode(token, options={"verify_signature": False})
#     logger.info(f"OIDC Token Decoded: {decoded}")

def assume_role_with_oidc(role_arn, aws_region, audience=None, session_name="GitHubOIDCSession"):
    request_token = os.getenv('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    request_url = os.getenv('ACTIONS_ID_TOKEN_REQUEST_URL')
    
    if not request_token or not request_url:
        raise ValueError("ACTIONS_ID_TOKEN_REQUEST_TOKEN or ACTIONS_ID_TOKEN_REQUEST_URL is not available in the environment.")

    if audience and "audience=" not in request_url:
            request_url += f"&audience={audience}"

    logger.info("Fetching OIDC token from GitHub Actions...")

    headers = {"Authorization": f"Bearer {request_token}"}
    response = requests.get(request_url, headers=headers)

    if response.status_code != 200:
        raise RuntimeError(f"Failed to fetch OIDC token: {response.status_code} {response.text}")

    oidc_token = response.json().get("value")
    if not oidc_token:
        raise RuntimeError("OIDC token not found in the response.")

    logger.info("Successfully fetched OIDC token.")

    # INFO: for debugging purposes
    # debug_oidc_token(oidc_token)

    # Exchange the OIDC token for temporary AWS credentials
    client = boto3.client('sts', region_name=aws_region)
    response = client.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        WebIdentityToken=oidc_token
    )
    return response['Credentials']

def get_secret(secret_name, region, credentials):
    client = boto3.client(
        'secretsmanager',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    response = client.get_secret_value(SecretId=secret_name)
    secret = response['SecretString']
    secret_dict = json.loads(secret)

    return secret_dict['Token']

def create_signature(payload, token):
    hmac_obj = hmac.new(token.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256)

    logger.info(f'secret: {hmac_obj}')
    logger.info(f'secret digest: {hmac_obj.hexdigest()}')

    return f"sha256={hmac_obj.hexdigest()}"

def send_webhook(url, token, content_type, headers, payload):
    headers = json.loads(headers) if headers else {}
    headers['Content-Type'] = content_type

    if token:
        # Generate the HMAC token
        hmac_token = create_signature(payload, token)
        headers['X-Hub-Signature-256'] = hmac_token

    response = requests.post(url, data=payload, headers=headers)

    logger.info(f'Webhook response status code: {response.status_code}')
    logger.info(f'Webhook response headers: {response.headers}')
    logger.info(f'Webhook response body: {response.text}')

    if response.status_code == 200:
        logger.info('Webhook sent successfully')
    else:
        logger.error(f'Failed to send webhook, status code: {response.status_code}')
        response.raise_for_status() 

def parse_args():
    parser = argparse.ArgumentParser(description="Send a webhook to a specified URL.")
    
    parser.add_argument('--webhook_url', help='The URL to send the webhook to.', required=True)
    parser.add_argument('--aws_region', help='The AWS region where the secret is stored.', required=True)
    parser.add_argument('--aws_role_to_assume', help='The AWS IAM role to assume for accessing Secrets Manager.', required=True)
    parser.add_argument('--audience', help='The audience parameter for OIDC token request.', required=False)
    parser.add_argument('--secret_name', help='The name of the secret in AWS Secrets Manager.', required=True)
    parser.add_argument('--content_type', help='Content-Type header for the request.', required=True)
    parser.add_argument('--headers', help='Optional additional headers to include in the webhook request.', required=False)
    parser.add_argument('--payload', help='The JSON payload to send in the webhook request.', required=True)

    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()

    logger.info(f"Assuming role with OIDC: {args.aws_role_to_assume}")
    credentials = assume_role_with_oidc(args.aws_role_to_assume, args.aws_region, args.audience)

    # Retrieve the secret
    logger.info(f"Fetching secret: {args.secret_name}")
    secret_token = get_secret(args.secret_name, args.aws_region, credentials)

    # Send the webhook
    send_webhook(args.webhook_url, secret_token, args.content_type, args.headers, args.payload)