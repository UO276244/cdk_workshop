from aws_cdk import (
    CfnOutput, CfnTag,
    aws_ec2 as ec2,
    aws_networkfirewall as networkfirewall,
    aws_logs as logs,
    Stack,
    Fn
)
from constructs import Construct
import networkingConfig
import json


class InspectionVpcStack(Stack):
    """
        Define the VPC that filters all traffic between VPCs and the Internet through the Network Firewall

        Parameters:
            Stack (Stack):
            https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk/Stack.html
    """
    @property
    def availability_zones(self):
        return networkingConfig.AVAILABILITY_ZONES

    @property
    def vpc(self):
        return self._VPC

    @property
    def rules(self):
        return self._RULES

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:

        super().__init__(scope=scope, id=id, **kwargs)

        # Read RULES data from json
        data = json.load(open("managed-rules.json"))
        rules = {}

        # Dictionary Key: rule name ;  Value: rule arn
        for rule in data['RuleGroups']:
            rules[rule['Name']] = rule['Arn']

        self._RULES = rules

        # Create the Inspection VPC
        self._VPC = self.create_vpc()

        # Create the VPC subnets
        self._subnets = self.create_subnets()

        # Subnets must be in at least 2 different AZs
        self._firewall_subnet_ids = [
            self._subnets[3].ref,
            self._subnets[4].ref
            # self._subnets[5].ref
        ]

        # Custom rules examples
        # self._add_rule_group_Telnet = self.add_rule_group_DenyTelnet()
        # self._add_rule_group_SuricataExample = self.add_rule_group_Suricata()
        # self._add_rule_group_Telnet = self.add_rule_group_AllowTelnet()

        # Create Network Firewall policy
        self._firewall = self.add_firewall_action_order()

        # Create flow log group
        self._log_group_flow = self.create_log_group_flow()

        # Create alert log group
        self._log_group_alert = self.create_log_group_alert()

        # Attach log groups to Network Firewall
        self._add_logging = self.add_logging()

        # self._VPC.add_deletion_override('Properties.RouteTableAssociation')
        # self._VPC.add_deletion_override('Properties.RouteTable')

        # for subnet in self._subnets:
        #     subnet.add_deletion_override('Properties.RouteTableAssociation')
        #     subnet.add_deletion_override('Properties.RouteTable')

        # Define the outputs
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk/CfnOutput.html
        CfnOutput(self, networkingConfig.INSPECTION_VPC_ID_NAME,
                  value=self._VPC.ref)
        CfnOutput(self, "firewall", value=Fn.select(
            0, self._firewall.attr_endpoint_ids), export_name="firewallkey")
        CfnOutput(self, "InspectionOutputVpc", value=self._VPC.ref,
                  export_name="InspectionOutputVpcid")
        CfnOutput(self, "InspectionOutputTGWSubnets", value=Fn.join(",", [
                  subnet.ref for subnet in self._subnets if "TGW-" in str(subnet.tags.tag_values()["Name"])
                  ]), export_name="InspectionOutputTGWSubnets")
        CfnOutput(self, "InspectionOutputFWSubnets", value=Fn.join(",", [
                  subnet.ref for subnet in self._subnets if "FW-" in str(subnet.tags.tag_values()["Name"])
                  ]), export_name="InspectionOutputFWSubnets")

    def create_vpc(self) -> ec2.CfnVPC:
        """
            Define the VPC resource given a IPv4 CIDR block in the config.py file

            Returns:
                ec2.CfnVPC: a CloudFormation VPC resource
        """
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_ec2/CfnVPC.html
        return ec2.CfnVPC(
            self,
            id=networkingConfig.INSPECTION_VPC_NAME,
            enable_dns_hostnames=True,
            enable_dns_support=True,
            cidr_block=networkingConfig.INSPECTION_VPC_CIDR_BLOCK,
            tags=[
                CfnTag(
                    key="Name",
                    value=networkingConfig.INSPECTION_VPC_NAME
                )
            ]
        )

    def create_subnets(self) -> list:
        """
            Define the Subnet resource given an AZ the config.py file

            Returns:
                list[ec2.CfnSubnet]: a list of ec2.CfnSubnet resources
        """
        subnets = []
        for subnet in networkingConfig.INSPECTION_SUBNETS_CONFIG:
            subnets.append(
                # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_ec2/CfnSubnet.html
                ec2.CfnSubnet(
                    self,
                    id=subnet["name"],
                    vpc_id=self._VPC.ref,
                    availability_zone=networkingConfig.AVAILABILITY_ZONES[subnet["az"]],
                    cidr_block=subnet["cidr_block"],
                    enable_dns64=False,
                    ipv6_native=False,
                    map_public_ip_on_launch=subnet["public?"],
                    tags=[
                        CfnTag(
                            key="Name",
                            value=subnet["name"]
                        )
                    ]
                )
            )
        return subnets

    def add_firewall_action_order(self) -> networkfirewall.CfnFirewall:
        """
            Define the Network Firewall policy and its rules

            Returns:
                networkfirewall.CfnFirewall: A Network Firewall resource
        """
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_networkfirewall/CfnFirewallPolicy.html#aws_cdk.aws_networkfirewall.CfnFirewallPolicy.FirewallPolicyProperty
        network_firewall_policy = networkfirewall.CfnFirewallPolicy(
            self, networkingConfig.INSPECTION_FIREWALL_POLICY_NAME,
            firewall_policy=networkfirewall.CfnFirewallPolicy.FirewallPolicyProperty(
                # Establish same behavior for stateless and stateful packets
                stateless_default_actions=["aws:forward_to_sfe"],
                stateless_fragment_default_actions=["aws:forward_to_sfe"],
                # stateless_default_actions=["aws:pass"],
                # stateless_fragment_default_actions=["aws:pass"],

                # the properties below are optional
                stateful_default_actions=[
                    # "aws:drop_strict",
                    # "aws:drop_established",
                    # "aws:alert_strict",
                    "aws:alert_established"
                ],
                # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_networkfirewall/CfnRuleGroup.html#aws_cdk.aws_networkfirewall.CfnRuleGroup.StatefulRuleOptionsProperty
                stateful_engine_options=networkfirewall.CfnFirewallPolicy.StatefulEngineOptionsProperty(
                    rule_order="STRICT_ORDER"  # | DEFAULT_ACTION_ORDER
                ),
                stateful_rule_group_references=[
                    # Custom rules example (Telnet protocol)
                    # networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                    #     resource_arn=self._add_rule_group_Telnet.ref,
                    # the properties below are optional
                    # priority=2
                    # ),

                    # networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                    #     resource_arn=self._add_rule_group_SuricataExample.ref,
                    # the properties below are optional
                    # priority=3
                    # ),

                     # ThreatSignaturesMalwareCoinmining [Detect malware that performs coin mining]
                        networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesMalwareCoinminingStrictOrder'],
                        priority = 5 # optional
                    ),

                    # ThreatSignaturesBotnetWeb [Detect HTTP Botnets]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesBotnetWebStrictOrder'],
                        priority = 10 # optional
                    ),

                    # ThreatSignaturesBotnetWindows [Detect Windows botnets]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesBotnetWindowsStrictOrder'],
                        priority = 15 # optional
                    ),

                    # ThreatSignaturesIOC [Detect Exploit Kits]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesIOCStrictOrder'],
                        priority = 20 # optional
                    ),

                    # ThreatSignaturesDoS [Detect Denegation of Service attacks]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesDoSStrictOrder'],
                        priority = 25 # optional
                    ),

                    # ThreatSignaturesEmergingEvents [Response to new attacks]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesEmergingEventsStrictOrder'],
                        priority = 30 # optional
                    ),

                    # ThreatSignaturesExploits [Detect attacks to ActiveX, FTP, ICMP, RPC, ShellCode, SNMP, Telnet, VOIP, SQL]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesExploitsStrictOrder'],
                        priority = 35 # optional
                    ),

                    # ThreatSignaturesFUP [Detect gaming traffic, inapropiate websites and P2P traffic]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesFUPStrictOrder'],
                        priority = 40 # optional
                    ),

                    # ThreatSignaturesMalwareMobile [Detect malware related to Android or iOS]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesMalwareMobileStrictOrder'],
                        priority = 45 # optional
                    ),

                    # ThreatSignaturesMalwareWeb [Detect malicious code in HTTP and TLS protocols]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesMalwareWebStrictOrder'],
                        priority = 50 # optional
                    ),

                    # ThreatSignaturesPhishing [Detect credential phising activity]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesPhishingStrictOrder'],
                        priority = 55 # optional
                    ),

                    # ThreatSignaturesScanners [Detech security breaches by scanning ports]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesScannersStrictOrder'],
                        priority = 60 # optional
                    ),

                    # ThreatSignaturesSuspect [Detect malicious SSL certificates]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesSuspectStrictOrder'],
                        priority = 65 # optional
                    ),

                    # ThreatSignaturesWebAttacks [Detect attacks and vulnerabilities in web servers, clients or apps]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['ThreatSignaturesWebAttacksStrictOrder'],
                        priority = 70 # optional
                    ),

                    # Domain list rule groups [https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-domain-list.html]

                    # BotNetCommandAndControlDomains [Block domains known for hosting Botnets]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['BotNetCommandAndControlDomainsStrictOrder'],
                        priority = 75 # optional
                    ),

                    # MalwareDomains [Block domains known for hosting malware]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['MalwareDomainsStrictOrder'],
                        priority = 80 # optional
                    ),

                    # AbusedLegitBotNetCommandAndControlDomains [Block legitimate domains compromised by Botnets]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['AbusedLegitBotNetCommandAndControlDomainsStrictOrder'],
                        priority = 85 # optional
                    ),

                    # AbusedLegitMalwareDomains [Block legitimate domains compromised by malware]
                    networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty(
                        resource_arn=self._RULES['AbusedLegitMalwareDomainsStrictOrder'],
                        priority = 90 # optional
                    )
                ]
            ),
            firewall_policy_name=networkingConfig.INSPECTION_FIREWALL_POLICY_NAME
        )
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_networkfirewall/CfnFirewall.html
        return networkfirewall.CfnFirewall(
            self,
            networkingConfig.INSPECTION_FIREWALL_NAME,
            firewall_name=networkingConfig.INSPECTION_FIREWALL_NAME,
            firewall_policy_arn=network_firewall_policy.get_att(
                'FirewallPolicyArn').to_string(),
            subnet_mappings=[
                networkfirewall.CfnFirewall.SubnetMappingProperty(
                    subnet_id=self._firewall_subnet_ids[0]
                ),
                networkfirewall.CfnFirewall.SubnetMappingProperty(
                    subnet_id=self._firewall_subnet_ids[1]
                )
                # networkfirewall.CfnFirewall.SubnetMappingProperty(subnet_id = self._firewall_subnet_ids[2])
            ],
            vpc_id=self._VPC.ref,
            delete_protection=False,
            description="Firewall running on Inspection VPC",
            firewall_policy_change_protection=False,
            # subnet_change_protection=False,
        )

    def add_rule_group_Suricata(self) -> networkfirewall.CfnRuleGroup:
        """
            Define Network Firewall rules directly from string

            Returns:
                networkfirewall.CfnRuleGroup: a Network Firewall Rule Group
        """
        return networkfirewall.CfnRuleGroup(
            self, "OwnSuricataRules",
            capacity=150,
            rule_group_name="OwnRules",
            type="STATEFUL",

            # the properties below are optional
            description="Demo Suricata Rules",
            # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_networkfirewall/CfnRuleGroup.html
            rule_group=networkfirewall.CfnRuleGroup.RuleGroupProperty(
                rules_source=networkfirewall.CfnRuleGroup.RulesSourceProperty(
                    rules_string="""
                        alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET USER_AGENTS Observed Suspicious UA (easyhttp client)"; flow:established,to_server; http.user_agent; content:"easyhttp client"; bsize:15; sid:2000000; rev:1; metadata:attack_target Client_Endpoint, created_at 2020_03_04, deployment Perimeter, former_category USER_AGENTS, signature_severity Informational, updated_at 2020_03_04;)
                        pass tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"amazon.com"; startswith; nocase; endswith; msg:"matching TLS denylisted FQDNs"; flow:to_server, established; sid:2000001; rev:1;)
                        pass http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"amazon.com"; startswith; endswith; msg:"matching HTTP denylisted FQDNs"; flow:to_server, established; sid:2000002; rev:1;)
                        pass tcp $HOME_NET any -> any 80 (msg:"Deny TCP 80"; sid:2000004; rev:1;)
                    """
                ),
                # the properties below are optional
                rule_variables=networkfirewall.CfnRuleGroup.RuleVariablesProperty(
                    ip_sets={
                        "HOME_NET": {
                            "definition": ["10.0.0.0/8"]
                        },
                        "HTTP_SERVERS": {
                            "definition": ["10.0.0.0/8"]
                        }
                    },
                    port_sets={
                        "HTTP_PORTS": networkfirewall.CfnRuleGroup.PortSetProperty(
                            definition=[
                                "80,443"]
                        )
                    }
                ),
                stateful_rule_options=networkfirewall.CfnRuleGroup.StatefulRuleOptionsProperty(
                    rule_order="STRICT_ORDER"
                )
            ),
            tags=[
                CfnTag(
                    key="Name",
                    value="SuricataRuleGroup"
                )
            ]
        )

    def add_rule_group_DenyIcmp(self) -> networkfirewall.CfnRuleGroup:
        """
            Define a Network Firewall rule to deny ICMP traffic from string

            Returns:
                networkfirewall.CfnRuleGroup: a Network Firewall Rule Group
        """
        return networkfirewall.CfnRuleGroup(
            self, "DenyIcmp",
            capacity=150,
            rule_group_name="DenyIcmp",
            type="STATEFUL",

            # the properties below are optional
            description="DenyIcmp",
            rule_group=networkfirewall.CfnRuleGroup.RuleGroupProperty(
                rules_source=networkfirewall.CfnRuleGroup.RulesSourceProperty(
                    rules_string="""
                    drop icmp $HOME_NET any -> 8.8.8.8 any (msg:"Drop ICMP"; icode:>0; sid:10002;)
                    """
                ),
                # the properties below are optional
                rule_variables=networkfirewall.CfnRuleGroup.RuleVariablesProperty(
                    ip_sets={
                        "HOME_NET": {
                            "definition": ["10.0.0.0/8"]
                        },
                        "HTTP_SERVERS": {
                            "definition": ["10.0.0.0/8"]
                        }
                    },
                    port_sets={
                        "HTTP_PORTS": networkfirewall.CfnRuleGroup.PortSetProperty(
                            definition=[
                                "80,443"]
                        )
                    }
                ),
                stateful_rule_options=networkfirewall.CfnRuleGroup.StatefulRuleOptionsProperty(
                    rule_order="STRICT_ORDER"
                )
            ),
            tags=[
                CfnTag(
                    key="Name",
                    value="DenyIcmp"
                )
            ]
        )

    def add_rule_group_DenyTelnet(self) -> networkfirewall.CfnRuleGroup:
        """
            Define a Network Firewall rule to deny Telnet traffic from string

            Returns:
                networkfirewall.CfnRuleGroup: a Network Firewall Rule Group
        """
        return networkfirewall.CfnRuleGroup(
            self, "DenyTelnet",
            capacity=150,
            rule_group_name="DenyTelnet",
            type="STATEFUL",

            # the properties below are optional
            description="DenyTelnet",
            rule_group=networkfirewall.CfnRuleGroup.RuleGroupProperty(
                rules_source=networkfirewall.CfnRuleGroup.RulesSourceProperty(
                    rules_string="""
                        drop tcp $HOME_NET any -> any 22 (msg:"Deny TCP 22"; sid:172192; rev:1;)
                    """
                ),
                # the properties below are optional
                rule_variables=networkfirewall.CfnRuleGroup.RuleVariablesProperty(
                    ip_sets={
                        "HOME_NET": {
                            "definition": ["10.0.0.0/8"]
                        },
                        "HTTP_SERVERS": {
                            "definition": ["10.0.0.0/8"]
                        }
                    },
                    port_sets={
                        "HTTP_PORTS": networkfirewall.CfnRuleGroup.PortSetProperty(
                            definition=[
                                "80,443"]
                        )
                    }
                ),
                stateful_rule_options=networkfirewall.CfnRuleGroup.StatefulRuleOptionsProperty(
                    rule_order="STRICT_ORDER"
                )
            ),
            tags=[
                CfnTag(
                    key="Name",
                    value="DenyTelnet"
                )
            ]
        )

    def add_rule_group_AllowTelnet(self):
        """
            Define a Network Firewall rule to allow Telnet traffic from string

            Returns:
                networkfirewall.CfnRuleGroup: a Network Firewall Rule Group
        """
        return networkfirewall.CfnRuleGroup(
            self, "AllowTelnet",
            capacity=150,
            rule_group_name="AllowTelnet",
            type="STATEFUL",

            # the properties below are optional
            description="AllowTelnet",
            rule_group=networkfirewall.CfnRuleGroup.RuleGroupProperty(
                rules_source=networkfirewall.CfnRuleGroup.RulesSourceProperty(
                    rules_string="""
                        alert tcp $HOME_NET any -> any 22 (msg:"alert TCP 22"; sid:172193; rev:1;)
                    """
                ),
                # the properties below are optional
                rule_variables=networkfirewall.CfnRuleGroup.RuleVariablesProperty(
                    ip_sets={
                        "HOME_NET": {
                            "definition": ["10.0.0.0/8"]
                        },
                        "HTTP_SERVERS": {
                            "definition": ["10.0.0.0/8"]
                        }
                    },
                    port_sets={
                        "HTTP_PORTS": networkfirewall.CfnRuleGroup.PortSetProperty(
                            definition=[
                                "80,443"]
                        )
                    }
                ),
                stateful_rule_options=networkfirewall.CfnRuleGroup.StatefulRuleOptionsProperty(
                    rule_order="STRICT_ORDER"
                )
            ),
            tags=[CfnTag(
                key="Name",
                value="AllowTelnet"
            )]
        )

    def create_log_group_flow(self):
        """
            Create a flow log group for the Network Firewall

            Returns:
                logs.CfnLogGroup: a CloudFormation log group for flow logs
        """
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_logs/CfnLogGroup.html
        return logs.CfnLogGroup(
            self, "log_group_flow",
            # kms_key_id="kmsKeyId",
            log_group_name="/aws/networkfirewallFlow/",
            retention_in_days=3,
            tags=[CfnTag(
                key="Name",
                value="FirewallLogsFlows"
            )
            ]
        )

    def create_log_group_alert(self):
        """
            Create an alert log group for the Network Firewall

            Returns:
                logs.CfnLogGroup: a CloudFormation log group for alert logs
        """
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_logs/CfnLogGroup.html
        return logs.CfnLogGroup(
            self, "log_group_alert",
            # kms_key_id="kmsKeyId",
            log_group_name="/aws/networkfirewallAlert/",
            retention_in_days=3,
            tags=[
                CfnTag(
                    key="Name",
                    value="FirewallLogsAlerts"
                )
            ]
        )

    def add_logging(self):
        """
            Attach flow and alert log groups to the Network Firewall in Cloudwatch

            Returns:
                networkfirewall.CfnLoggingConfiguration: a Network Firewall logging configuration
        """
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_networkfirewall/CfnLoggingConfiguration.html
        return networkfirewall.CfnLoggingConfiguration(
            self, "MyCfnLoggingConfiguration",
            firewall_arn=self._firewall.ref,
            logging_configuration=networkfirewall.CfnLoggingConfiguration.LoggingConfigurationProperty(
                log_destination_configs=[
                    networkfirewall.CfnLoggingConfiguration.LogDestinationConfigProperty(
                        log_destination={
                            "logGroup": self._log_group_alert.ref
                        },
                        log_destination_type="CloudWatchLogs",
                        log_type="ALERT"
                    ),
                    networkfirewall.CfnLoggingConfiguration.LogDestinationConfigProperty(
                        log_destination={
                            "logGroup": self._log_group_flow.ref
                        },
                        log_destination_type="CloudWatchLogs",
                        log_type="FLOW"
                    )
                ],
            )
        )
