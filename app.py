#!/usr/bin/env python3

import aws_cdk as cdk

from cdk_workshop.cdk_workshop_stack import CdkWorkshopStack
#cuenta martin: 733775831366
#mi cuenta ntt: 936716798377
env_networking = cdk.Environment(account="733775831366", region="eu-west-1")

app = cdk.App()
#inspectionVpc = InspectionVpcStack(app, "InspectionVPCStack",env=env_networking)

CdkWorkshopStack(app, "CdkWorkshopStack", env=env_networking)

app.synth()
