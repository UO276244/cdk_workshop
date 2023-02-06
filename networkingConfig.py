# GLOBAL PARAMETERS
AVAILABILITY_ZONES = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
AVAILABILITY_ZONES_ID = ['', '', '']
MAX_AVAILABILITY_ZONES = 3

# INCOMING VPC
INCOMING_VPC_NAME = "IncomingVPC"
INCOMING_VPC_ID_NAME = "IncomingVpcID"
INCOMING_VPC_CIDR_BLOCK = '10.5.24.0/21'
INCOMING_INTERNET_GATEWAY_NAME = "IncomingIGW"
INCOMING_VPC_GATEWAY_ATTACHMENT_NAME = "MyCfnVPCGatewayAttachment"
INCOMING_ALB_NAME = "ALB"
INCOMING_SUBNETS_CONFIG = [
    {
        "name": "IncomingTGW-A",
        "cidr_block": "10.5.25.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "IncomingTGW-B",
        "cidr_block": "10.5.26.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "IncomingTGW-C",
        "cidr_block": "10.5.27.0/24",
        "az": 2,
        "public?": False,
    },
    {
        "name": "IncomingAlb-A",
        "cidr_block": "10.5.28.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "IncomingAlb-B",
        "cidr_block": "10.5.29.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "IncomingAlb-C",
        "cidr_block": "10.5.30.0/24",
        "az": 2,
        "public?": False,
    }
]
INCOMING_DISTRIBUTION_DOMAINS = [
    "www.example.com"
]

# OUTCOMING VPC
OUTCOMING_VPC_NAME = "OutcomingVPC"
OUTCOMING_VPC_ID_NAME = "OutcomingVpcID"
OUTCOMING_VPC_CIDR_BLOCK = '10.5.32.0/21'
OUTCOMING_INTERNET_GATEWAY_NAME = "OutcomingIGW"
OUTCOMING_VPC_GATEWAY_ATTACHMENT_NAME = "OutcomingIGWAttachment"
OUTCOMING_SUBNETS_CONFIG = [
    {
        "name": "OutcomingTGW-A",
        "cidr_block": "10.5.33.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "OutcomingTGW-B",
        "cidr_block": "10.5.34.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "OutcomingTGW-C",
        "cidr_block": "10.5.35.0/24",
        "az": 2,
        "public?": False,
    },
    {
        "name": "OutcomingNatGW-A",
        "cidr_block": "10.5.36.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "OutcomingNatGW-B",
        "cidr_block": "10.5.37.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "OutcomingNatGW-C",
        "cidr_block": "10.5.38.0/24",
        "az": 2,
        "public?": False,
    }
]

# INSPECTION VPC
INSPECTION_VPC_NAME = "InspectionVPC"
INSPECTION_VPC_ID_NAME = "InspectionVpcID"
INSPECTION_VPC_CIDR_BLOCK = '10.5.16.0/21'
INSPECTION_FIREWALL_NAME = "NetworkFirewall"
INSPECTION_FIREWALL_POLICY_NAME = "NetworkFirewallPolicy"
INSPECTION_SUBNETS_CONFIG = [
    {
        "name": "InspectionTGW-A",
        "cidr_block": "10.5.17.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "InspectionTGW-B",
        "cidr_block": "10.5.18.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "InspectionTGW-C",
        "cidr_block": "10.5.19.0/24",
        "az": 2,
        "public?": False,
    },
    {
        "name": "InspectionFW-A",
        "cidr_block": "10.5.20.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "InspectionFW-B",
        "cidr_block": "10.5.22.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "InspectionFW-C",
        "cidr_block": "10.5.23.0/24",
        "az": 2,
        "public?": False,
    }
]

# ENDPOINTS VPC
ENDPOINTS_VPC_NAME = "EndpointsVPC"
ENDPOINTS_VPC_ID_NAME = "EndpointsVpcID"
ENDPOINTS_VPC_CIDR_BLOCK = '10.5.8.0/21'
ENDPOINTS_SUBNETS_CONFIG = [
    {
        "name": "EndpointsTGW-A",
        "cidr_block": "10.5.9.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "EndpointsTGW-B",
        "cidr_block": "10.5.10.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "EndpointsTGW-C",
        "cidr_block": "10.5.11.0/24",
        "az": 2,
        "public?": False,
    },
    {
        "name": "EndpointsEndpoints-A",
        "cidr_block": "10.5.12.0/24",
        "az": 0,
        "public?": False,
    },
    {
        "name": "EndpointsEndpoints-B",
        "cidr_block": "10.5.13.0/24",
        "az": 1,
        "public?": False,
    },
    {
        "name": "EndpointsEndpoints-C",
        "cidr_block": "10.5.14.0/24",
        "az": 2,
        "public?": False,
    }
]

# NETWORKING - TGW
TRANSIT_GATEWAY_NAME = "My Transit GW"
TRANSIT_GATEWAY_DESCRIPTION = "Description"
TRANSIT_GATEWAY_CIDR_BLOCK = ["10.0.0.0/24"]
GATEWAY_VPC_ATTACHMENT_NAMESET = [
    "IncomingAttachmentsTGW",
    "InspectionAttachmentsTGW",
    "OutcomingAttachmentsTGW",
    "WorkloadAttachmentsTGW",
    "EndpointAttachmentsTGW"]

# ROUTE53

# CDN - WAF

# NLB
NLB_PRIVATE_IPS = [
    ["10.6.80.184", "a"],
    ["10.6.144.251", "b"],
    ["10.6.237.127", "c"]
]

# VPN
VPN_ID = "cgwA"
VPN_BGP_ASN = 32982
VPN_TYPE = "ipsec.1"
VPN_IP_ADDRESS_ONPREMISE = "203.47.143.101"

# OWNDNS VPC
# OWNDNS_VPC_NAME = "OwnDNSVPC"
# OWNDNS_VPC_ID_NAME = "OwnDNSVpcID"
# OWNDNS_VPC_CIDR_BLOCK = '10.5.40.0/21'
# OWNDNS_SUBNETS_CONFIG = [
#     {
#         "name": "TransitGW1",
#         "cidr_block": "10.5.41.0/24",
#         "az": 0,
#         "public?": False,
#     },
#     {
#         "name": "TransitGW2",
#         "cidr_block": "10.5.42.0/24",
#         "az": 1,
#         "public?": False,
#     },
#     {
#         "name": "TransitGW3",
#         "cidr_block": "10.5.43.0/24",
#         "az": 2,
#         "public?": False,
#     },
#     {
#         "name": "NATGW1",
#         "cidr_block": "10.5.44.0/24",
#         "az": 0,
#         "public?": False,
#     },
#     {
#         "name": "NATGW2",
#         "cidr_block": "10.5.45.0/24",
#         "az": 1,
#         "public?": False,
#     },
#     {
#         "name": "NATGW3",
#         "cidr_block": "10.5.46.0/24",
#         "az": 2,
#         "public?": False,
#     }
# ]
