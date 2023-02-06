from aws_cdk import (
    Stack,
    aws_lambda as _lambda,
    assertions
)

from cdk_workshop.hitcounter import HitCounter

import pytest


#This test is simply testing to ensure that the synthesized stack includes a DynamoDB table.
def test_dynamodb_table_created():
    stack = Stack()
    HitCounter(stack, "HitCounter",
            downstream=_lambda.Function(
                stack, 
                "TestFunction",
                runtime=_lambda.Runtime.PYTHON_3_7,
                handler='hello.handler',
                code=_lambda.Code.from_asset('components/lambda')
            ),
    )
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::DynamoDB::Table", 1)



#At this point we don’t really know what the value of the function_name or 
#table_name will be since the CDK will calculate a hash to append to the end 
#of the name of the constructs, so we will just use a dummy value for now. 
# Once we run the test it will fail and show us the expected value.
def test_lambda_has_env_vars():
    stack = Stack()

    HitCounter(
        stack,
        "HitCounter",
        downstream= _lambda.Function(
            stack,
            "TestFuntion",
            runtime = _lambda.Runtime.PYTHON_3_7,
            handler = 'hello.handler',
            code = _lambda.Code.from_asset('components/lambda')
        )
    )


    template = assertions.Template.from_stack(stack)
    envCapture = assertions.Capture()

    template.has_resource_properties(
        "AWS::Lambda::Function", {
            "Handler" : "hitcount.handler",
            "Environment" : envCapture
        }
    )


    assert envCapture.as_object() == {
        "Variables" : {
            "DOWNSTREAM_FUNCTION_NAME": {"Ref": "TestFuntion46FCAA82"},
            "HITS_TABLE_NAME": {"Ref": "HitCounterHits079767E5"},
        }
    }

def test_dynamobd_with_encryption():
    stack = Stack()

    HitCounter(
       stack,
       'HitCounter',
       downstream= _lambda.Function(
            stack,
            'Test Function',
            runtime = _lambda.Runtime.PYTHON_3_7,
            handler = 'hello.handler',
            code = _lambda.Code.from_asset('components/lambda')
        )
    )

    template = assertions.Template.from_stack(stack)
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "SSESpecification": {
            "SSEEnabled": True,
            },
        })

    
def test_dynamodb_raises():
    stack = Stack()
    with pytest.raises(Exception):
        HitCounter(
            stack, 
            "HitCounter",
            downstream=_lambda.Function(stack, "TestFunction",
                runtime=_lambda.Runtime.PYTHON_3_7,
                handler='hello.handler',
                code=_lambda.Code.from_asset('lambda')),
            read_capacity=1, #this launches exception
        )
