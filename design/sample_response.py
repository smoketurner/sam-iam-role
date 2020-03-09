response = {
    "EvaluationResults": [
        {
            "EvalActionName": "xray:puttracesegments",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 485},
                    "EndPosition": {"Line": 1, "Column": 695},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:generatedatakeypair",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "logs:createloggroup",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 198},
                    "EndPosition": {"Line": 1, "Column": 300},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "logs:putlogevents",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "xray:getsamplingstatisticsummaries",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 485},
                    "EndPosition": {"Line": 1, "Column": 695},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "ec2:describenetworkinterfaces",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 41},
                    "EndPosition": {"Line": 1, "Column": 198},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:generatedatakeypairwithoutplaintext",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "ec2:deletenetworkinterface",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 41},
                    "EndPosition": {"Line": 1, "Column": 198},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "ec2:createnetworkinterface",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 41},
                    "EndPosition": {"Line": 1, "Column": 198},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:generatedatakeywithoutplaintext",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:decrypt",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:generatedatakey",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:reencryptfrom",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "xray:puttelemetryrecords",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 485},
                    "EndPosition": {"Line": 1, "Column": 695},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "xray:getsamplingtargets",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 485},
                    "EndPosition": {"Line": 1, "Column": 695},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:describekey",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "xray:getsamplingrules",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 485},
                    "EndPosition": {"Line": 1, "Column": 695},
                }
            ],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:reencryptto",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "logs:createlogstream",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
        {
            "EvalActionName": "kms:encrypt",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "MissingContextValues": [],
        },
    ],
    "IsTruncated": False,
    "ResponseMetadata": {
        "RequestId": "031796bc-ada8-445e-aca5-c2777a6eeaef",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "x-amzn-requestid": "031796bc-ada8-445e-aca5-c2777a6eeaef",
            "content-type": "text/xml",
            "content-length": "9238",
            "vary": "accept-encoding",
            "date": "Sun, 08 Mar 2020 14:40:27 GMT",
        },
        "RetryAttempts": 0,
    },
}

