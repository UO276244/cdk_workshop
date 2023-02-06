""" from constructs import Construct
from aws_cdk import (
    Stack,
    aws_codecommit as codecommit,
    pipelines as pipelines
)

class WorkshopPipelineStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        ## Creates a CodeCommit repository called 'WorkshopRepo'
        repo = codecommit.Repository(
            self,
            'WorkshopRepo',
            repository_name = 'WorkshopRepo'
        )

        pipeline = pipelines.CodePipeline( #This initializes the pipeline with the required values.
            self,
            'Pipeline',
            #First step: synth
            synth = pipelines.ShellStep( #The synth of the pipeline describes the commands necessary to install dependencies, build, and synth the CDK application from source.
                "Synth",
                #The input of the synth step specifies the repository where the CDK source code is stored
                input = pipelines.CodePipelineSource.code_commit(
                    repo,
                    commands = [
                        "npm install -g aws-cdk",  # Installs the cdk cli on Codebuild
                        "pip install -r requirements.txt", # Instructs Codebuild to install required packages
                        "cdk synth"
                    ]
                )
            )
        ) """