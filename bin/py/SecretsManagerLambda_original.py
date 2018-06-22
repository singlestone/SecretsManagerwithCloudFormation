from __future__ import print_function
from botocore.exceptions import ClientError

import boto3
import json
import logging
from urllib.request import urlopen, Request, HTTPError, URLError
from urllib.parse import urlencode

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SUCCESS = 'SUCCESS'
FAILED = 'FAILED'

def lambda_handler(event, context):

    secret_result = {}
    # Get values from Resource Properties
    secret_name = event['ResourceProperties']['SecretName']
    region_name = event['ResourceProperties']['Region']

    # Mask Password before logging to Cloudwatch!!
    if event['ResourceProperties']['SecretAction'] == 'upsert':
        try:
            secret_pwd = event['ResourceProperties']['SecretPassword']
            password = 'provided'
            event['ResourceProperties']['SecretPassword'] = '********'
        except Exception as e:
            password = 'generate'
            event['ResourceProperties']['SecretPassword'] = 'random generated'

    # Log event data to Cloudwatch
    logger.info("***** Received event. Full parameters: {}".format(json.dumps(event)))

    # Create response dict
    response = {
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Status": SUCCESS,
        "NoEcho": True,
        "Data": {}
    }

    if event.get('PhysicalResourceId', False):
        response['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        response['PhysicalResourceId'] = event['LogicalResourceId'] + '-12345'

    if event['RequestType'] == 'Create':
        logger.info('***** This is a Cloudwatch Create request - Evaluating specified SecretAction... *****')
        if event['ResourceProperties']['SecretAction'] == 'get':
            logger.info('***** SecretAction is `get` - Getting value for secret: %s *****' % (secret_name))
            secret_result = get_secret(secret_name=secret_name, region_name=region_name)
            if secret_result.get("Error", False):
                response['Status'] = FAILED
                response['Reason'] = secret_result['Error']['Message']
            else:
                logger.info('***** Value for secret %s successfully retrieved *****' % (secret_name))
                secret_string_json = json.loads(secret_result['SecretString'])
                response['PhysicalResourceId'] = secret_result['ARN']
                response['Data']['SecretPassword'] = secret_string_json['password']
            secret_result = json.dumps(secret_result, indent=4, sort_keys=True, default=str)

        else:
            if password == 'provided':
                logger.info('***** SecretAction is `upsert` - Creating or updating secret: %s with provide password *****' % (secret_name))
            else:
                logger.info('***** SecretAction is `upsert` - Creating or updating secret %s with randomly generated password *****' % (secret_name))
                secret_pwd = generate_secret_pwd(region_name=region_name)
                response['Data']['SecretPassword'] = secret_pwd
            secret_username = event['ResourceProperties']['SecretUserName']
            secret_desc = event['ResourceProperties']['SecretDescription']
            secret_result = upsert_secret(secret_name=secret_name, secret_username=secret_username, secret_pwd=secret_pwd, secret_desc=secret_desc, region_name=region_name)
            if secret_result.get('Error', False):
                response['Status'] = FAILED
                response['Reason'] = secret_result['Error']['Message']
            else:
                response['PhysicalResourceId'] = secret_result['ARN']

    else:
        logger.info('***** This is not a CloudFormation Create request - No AWS Secrets Manager actions performed. *****')

    serialized = json.dumps(response)
    req_data = serialized.encode('utf-8')

    ## Mask the password before logging out the CloudFormation response
    response['Data']['SecretPassword'] = '********'
    serialized = json.dumps(response)
    logger.info("***** Responding to CloudFormation with: %s *****" % (serialized))

    req = Request(
        event['ResponseURL'],
        data=req_data,
        headers={'Content-Length': len(req_data),
                 'Content-Type': ''}
    )
    req.get_method = lambda: 'PUT'

    try:
        urlopen(req)
        logger.info('***** Request to CFN API succeeded, nothing to do here *****')
    except HTTPError as e:
        logger.error('>>>>> Callback to CFN API failed with status %d <<<<<' % e.code)
        logger.error('>>>>> Response: %s' % e.reason)
    except URLError as e:
        logger.error('>>>>> Failed to reach the server - %s <<<<<' % e.reason)

    return secret_result

def generate_secret_pwd(region_name):
    endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )
    secret_pwd = client.get_random_password()
    secret_pwd = secret_pwd['RandomPassword']
    return secret_pwd

def get_secret(secret_name, region_name):
    endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        get_secret_response = client.get_secret_value(SecretId=secret_name)

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error('>>>>> The specified secret cannot be found - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            logger.error('>>>>> The requested secret cannot be decrypted - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error('>>>>> The request was invalid - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error('>>>>> The request had invalid parameters - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'InternalServiceError':
            logger.error('>>>>> An error occurred on the server side - the full error message is: %s <<<<<' % e)
            return e.response

    return get_secret_response

def upsert_secret(secret_name, secret_username, secret_pwd, secret_desc, region_name):
    endpoint_url = 'https://secretsmanager.us-east-1.amazonaws.com'
    secret_string = json.dumps({'username':secret_username,'password':secret_pwd})

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        upsert_secret_response = client.create_secret(
            Name=secret_name,
            Description=secret_desc,
            SecretString=secret_string
        )
        logger.info('***** The requested secret %s has been successfully created *****' % secret_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceExistsException':
            try:
                put_secret_value_response = client.put_secret_value(
                    SecretId=secret_name,
                    SecretString=secret_string
                )
                logger.info('***** The requested secret %s has been successfully updated *****' % secret_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidRequestException':
                    logger.error('>>>>> The request was invalid - the full error message is: %s <<<<<' % e)
                    return e.response
                elif e.response['Error']['Code'] == 'InvalidParameterException':
                    logger.error('>>>>> The request had invalid parameters - the full error message is: %s <<<<<' % e)
                    return e.response
                elif e.response['Error']['Code'] == 'EncryptionFailure':
                    logger.error('>>>>> The requested secret cannot be encrypted - the full error message is: %s <<<<<' % e)
                    return e.response
                elif e.response['Error']['Code'] == 'InternalServiceError':
                    logger.error('>>>>> An error occurred on the server side - the full error message is: %s <<<<<' % e)
                    return e.response
                elif e.response['Error']['Code'] == 'LimitExceededException':
                    logger.error('>>>>> The request exceeds Secrets Manager internal limits - the full error message is: %s <<<<<' % e)
                    return e.response
                elif e.response['Error']['Code'] == 'MalformedPolicyDocumentException':
                    logger.error('>>>>> The policy provided is invalid - the full error message is: %s <<<<<' % e)
                    return e.response
            return put_secret_value_response
        if e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error('>>>>> The request was invalid - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error('>>>>> The request had invalid parameters - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'EncryptionFailure':
            logger.error('>>>>> The requested secret cannot be encrypted - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'InternalServiceError':
            logger.error('>>>>> An error occurred on the server side - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'LimitExceededException':
            logger.error('>>>>> The request exceeds Secrets Manager internal limits - the full error message is: %s <<<<<' % e)
            return e.response
        elif e.response['Error']['Code'] == 'MalformedPolicyDocumentException':
            logger.error('>>>>> The policy provided is invalid - the full error message is: %s <<<<<' % e)
            return e.response
    return upsert_secret_response
