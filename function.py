import requests
import json
import boto3
from boto3.session import Session
import pprint
import os
from requests_aws4auth import AWS4Auth


def lambda_handler(event, context):
    try:
        credentials = get_credential()
    except Exception as e:
        pprint(e)
        print('NG')
        return

    access_key_id = credentials['AccessKeyId']
    secret_access_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]
    region_name = 'ap-northeast-1'
    auth = AWS4Auth(access_key_id, secret_access_key, region_name, 'appsync', session_token=session_token)

    user_id = event['userName']
    headers = {'Content-Type': 'application/graphql'}

    if not exists_user(user_id, auth, headers):
        create_user(user_id, auth, headers)

    return event


def exists_user(user_id, auth, headers):
    params = {'query': 'query {{getUser(UserId: "{0}") {{UserId NotifyToken NotifyTime SearchWords}}}}'.format(user_id)}
    response = requests.post(os.environ['APP_SYNC_URL'], headers=headers, data=json.dumps(params), auth=auth)
    data = json.loads(response.text)['data']
    user = data['getUser']
    return bool(user)


def create_user(user_id, auth, headers):
    query = 'mutation    {{createUser(UserId: "{0}") {{UserId NotifyToken NotifyTime SearchWords}}}}'.format(user_id)
    params = {'query': query}
    response = requests.post(os.environ['APP_SYNC_URL'], headers=headers, data=json.dumps(params), auth=auth)
    print(response)


def get_credential():
    if os.environ.get('EXEC_ENV') == 'TEST':
        session = Session(profile_name='local-dynamodb-user')
        sts = session.client('sts')
    else:
        sts = boto3.client('sts')

    role_arn = os.environ['ROLE_ARN']
    role = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='test',
        )
    return role['Credentials']

