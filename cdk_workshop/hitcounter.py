
from constructs import Construct
from aws_cdk import (
   
    Stack,
    aws_lambda as _lambda,
    aws_apigateway as apigw,
    aws_dynamodb as ddb,
    RemovalPolicy #by default, Dynamo table is not removed, we have to tell CDK to do it
   
)


#new construct HitCiunter
class HitCounter(Construct):

    #Expose handler as a public property so father construct can access it
    @property
    def handler(self):
        return self._handler

    @property
    def table(self):
        return self._table

    #constructor arguments are scope, id and kwargs
    def __init__(self, scope: Construct, id: str, downstream: _lambda.IFunction, read_capacity: int = 5, **kwargs):
        #parameter downstream of type lambda.IFunction:
        #This is where we are going to “plug in” the Lambda function we need to count calls for.

        if read_capacity < 5 or read_capacity > 20:
            raise ValueError("readCapacity must be between [5-20) ")

        super().__init__(scope, id, **kwargs) #we propagate arguments to the cdk.Construct base class



# defined a DynamoDB table with path as the partition key (every DynamoDB table must have a single partition key).
        self._table = ddb.Table(
            self,
            'Hits',
            partition_key= { 
                'name' : 'path',
                'type' : ddb.AttributeType.STRING
                },
            removal_policy=RemovalPolicy.DESTROY,
            encryption=ddb.TableEncryption.AWS_MANAGED,
            read_capacity= read_capacity
        )



#Lambda function encapsulating code in components/lambda/hitcounter.py handler() func
        self._handler = _lambda.Function( 
            self,
            'HitCounterHandler',
            runtime = _lambda.Runtime.PYTHON_3_7,
            handler = 'hitcount.handler',
            code = _lambda.Code.from_asset('components/lambda'),
            environment = { #We wired the Lambda’s environment variables to the function_name and table_name of our resources
                'DOWNSTREAM_FUNCTION_NAME' : downstream.function_name,
                'HITS_TABLE_NAME' : self._table.table_name,
            }
        )


        #The lambda counter function need access to be allowed to write in the dynamo table:
        self._table.grant_read_write_data(self._handler)
        #Also, counter lambda need permissions to invoke other lambda function (downstream):
        downstream.grant_invoke(self._handler)
