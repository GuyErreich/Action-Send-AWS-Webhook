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

ACTIONS_ID_TOKEN_REQUEST_TOKEN = os.getenv('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
ACTIONS_ID_TOKEN_REQUEST_URL = os.getenv('ACTIONS_ID_TOKEN_REQUEST_URL')

if not ACTIONS_ID_TOKEN_REQUEST_TOKEN or not ACTIONS_ID_TOKEN_REQUEST_URL:
    raise ValueError("Environment variables 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' or 'ACTIONS_ID_TOKEN_REQUEST_URL' are missing.")


def fetch_oidc_token(request_token, request_url, audience=None):
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

    return oidc_token


def assume_role_with_oidc(role_arn, aws_region, oidc_token, session_name="GitHubOIDCSession"):
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
    return f"sha256={hmac_obj.hexdigest()}"


def send_webhook(url, token, content_type, headers, payload):
    headers = json.loads(headers) if headers else {}
    headers['Content-Type'] = content_type

    if token:
        hmac_token = create_signature(payload, token)
        headers['X-Hub-Signature-256'] = hmac_token

    response = requests.post(url, data=payload, headers=headers)

    logger.info(f'Webhook response status code: {response.status_code}')
    logger.info(f'Webhook response body: {response.text}')

    if response.status_code == 200:
        logger.info('Webhook sent successfully')
    else:
        logger.error(f'Failed to send webhook, status code: {response.status_code}')
        response.raise_for_status()


def parse_args():
    parser = argparse.ArgumentParser(description="Send a webhook to a specified URL.")

    parser.add_argument('--webhook_url', required=True, help='The URL to send the webhook to.')
    parser.add_argument('--aws_region', required=True, help='The AWS region where the secret is stored.')
    parser.add_argument('--aws_role_to_assume', required=True, help='The AWS IAM role to assume for accessing Secrets Manager.')
    parser.add_argument('--audience', help='The audience parameter for OIDC token request.')
    parser.add_argument('--secret_name', required=True, help='The name of the secret in AWS Secrets Manager.')
    parser.add_argument('--content_type', required=True, help='Content-Type header for the request.')
    parser.add_argument('--headers', help='Optional additional headers to include in the webhook request.')
    parser.add_argument('--payload', required=True, help='The JSON payload to send in the webhook request.')

    return parser.parse_args()

def main():
    args = parse_args()

    logger.info(f"Assuming role with OIDC: {args.aws_role_to_assume}")

    # Fetch OIDC token
    oidc_token = fetch_oidc_token(ACTIONS_ID_TOKEN_REQUEST_TOKEN, ACTIONS_ID_TOKEN_REQUEST_URL, args.audience)

    # Assume role with OIDC token
    credentials = assume_role_with_oidc(args.aws_role_to_assume, args.aws_region, oidc_token)

    # Retrieve the secret
    logger.info(f"Fetching secret: {args.secret_name}")
    secret_token = get_secret(args.secret_name, args.aws_region, credentials)

    # Send the webhook
    send_webhook(args.webhook_url, secret_token, args.content_type, args.headers, args.payload)

if __name__ == '__main__':
    main()