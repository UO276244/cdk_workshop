import json
import os
import boto3

import aws_cdk.aws_dynamodb as dynamo #no sé por qué el tutorial oficial usa boto3 en vez de la libreria dybamoBD oficial

ddb = boto3.resource('dynamobd')

#Use of os.environ => we do not know the name of the table/downs.-func until
# we deploy the app. These names are created in upper construct (HitCounter) containing the S3 and Lambda AWS

#Environment var: NAME OF DynamoDB table to use for storage.
table = ddb.Table(os.environ['HITS_TABLE_NAME']) 
_lambda = boto3.client('lambda')


#Code to be xec. by lambda func:
def handler(event, context):
    print('request: {}'.format(json.dumps(event)))

    table.update_item(
        Key={'path': event['path']},
        UpdateExpression='ADD hits :incr',
        ExpressionAttributeValues={':incr': 1}
    )


    resp = _lambda.invoke(
        #Env. var:  name of the downstream AWS Lambda function.
        FunctionName=os.environ['DOWNSTREAM_FUNCTION_NAME'],
        Payload=json.dumps(event),
    )

    body = resp['Payload'].read()

    print('downstream response: {}'.format(body))

    return json.loads(body)