from __future__ import print_function
from botocore.exceptions import ClientError

import boto3
import json
import logging
from urllib.request import urlopen, Request, HTTPError, URLError
from urllib.parse import urlencode

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):


    # Initialize secret_result dict
    secret_result = {}

    # Capture SecretPassword from event object into secret_pwd var
    # And mask SecretPassword before logging to Cloudwatch!!
    secret_pwd = capture_and_mask_password(event)

    # Log event data to Cloudwatch
    logger.info("***** Received event. Full parameters: {}".format(json.dumps(event)))

    # Initialize the CloudFormation response dict
    response = {
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Status": "SUCCESS",
        "NoEcho": True,
        "Data": {}
    }

    # Assign the physical resource id
    response['PhysicalResourceId'] = physical_resource_id(event)

    # Only execute AWS Secrets Manager actions on CloudFormation Create requests
    if event['RequestType'] == 'Create':
        logger.info('***** This is a Cloudwatch Create request - Evaluating specified SecretAction... *****')
        if event['ResourceProperties']['SecretAction'] == 'get':
            secret_result,response = get_secret_password(event=event, response=response)
        else:
            secret_result,response = create_or_update_secret(event=event, response=response, secret_pwd=secret_pwd)
    else:
        logger.info('***** This is not a CloudFormation Create request - No AWS Secrets Manager actions performed. *****')

    # Construct and send a response to CloudFormation
    respond_to_cloudformation(event=event, response=response)

    return secret_result

# If this is an upsert action and a SecretPassword was provided,
# capture it from the event object and then mask it
def capture_and_mask_password(event):
    if event['ResourceProperties']['SecretAction'] == 'upsert':
        try:
            secret_pwd = event['ResourceProperties']['SecretPassword']
            event['ResourceProperties']['SecretPassword'] = '********'
            return secret_pwd
        except Exception as e:
            event['ResourceProperties']['SecretPassword'] = 'random generated'
            return 'generate'

# Return the event object physical_resource_id
def physical_resource_id(event):
    if event.get('PhysicalResourceId', False):
        return event['PhysicalResourceId']
    return event['LogicalResourceId'] + '-12345'

# Generate and return a random string for a password
# Uses straight defaults for get_random_password method
def generate_secret_pwd(region_name):

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )
    secret_pwd = client.get_random_password()
    secret_pwd = secret_pwd['RandomPassword']
    return secret_pwd

# Wrapper function that implements the `get` action
# Calls the get_secret fucntion to retrieve the password for a given SecretName
def get_secret_password(event, response):
    secret_name = event['ResourceProperties']['SecretName']
    region_name = event['ResourceProperties']['Region']
    logger.info('***** SecretAction is `get` - Getting value for secret: %s *****' % (secret_name))
    secret_result = get_secret(secret_name=secret_name, region_name=region_name)
    if secret_result.get("Error", False):
        response['Status'] = "FAILED"
        response['Reason'] = secret_result['Error']['Message']
    else:
        logger.info('***** Value for secret %s successfully retrieved *****' % (secret_name))
        secret_string_json = json.loads(secret_result['SecretString'])
        response['PhysicalResourceId'] = secret_result['ARN']
        response['Data']['SecretPassword'] = secret_string_json['password']
    return json.dumps(secret_result, indent=4, sort_keys=True, default=str),response

# Calls the get_secret_value method to retrieve the password for a given SecretName
def get_secret(secret_name, region_name):

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
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

# Wrapper funcion that implements the `upsert` action
# Calls the generate_secret_pwd method to generate a random string for the password
# Calls the upsert_secret function to create or update the requested SecretName
def create_or_update_secret(event, response, secret_pwd):
    secret_name = event['ResourceProperties']['SecretName']
    region_name = event['ResourceProperties']['Region']
    if secret_pwd == 'generate':
        logger.info('***** SecretAction is `upsert` - Creating or updating secret %s with randomly generated password *****' % (secret_name))
        secret_pwd = generate_secret_pwd(region_name=region_name)
        response['Data']['SecretPassword'] = secret_pwd
    else:
        logger.info('***** SecretAction is `upsert` - Creating or updating secret: %s with provided password *****' % (secret_name))

    secret_result = upsert_secret(event=event, secret_pwd=secret_pwd)
    if secret_result.get('Error', False):
        response['Status'] = "FAILED"
        response['Reason'] = secret_result['Error']['Message']
    else:
        response['PhysicalResourceId'] = secret_result['ARN']

    return secret_result,response

# Calls the create_secret method to create the requested SecretName, or
# calls the put_secret_value method to update the requested SecretName
def upsert_secret(event, secret_pwd):
    region_name = event['ResourceProperties']['Region']
    secret_username = event['ResourceProperties']['SecretUserName']
    secret_desc = event['ResourceProperties']['SecretDescription']
    secret_name = event['ResourceProperties']['SecretName']
    secret_string = json.dumps({'username':secret_username,'password':secret_pwd})

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
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

# Serialize, encode, and post the response object to CloudFormation
def respond_to_cloudformation(event, response):
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
