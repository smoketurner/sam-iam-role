response = {
    "EvaluationResults": [
        {
            "EvalActionName": "s3:GetObject",
            "EvalResourceName": "arn:aws:s3:::smoketurner-test-iam-bucket/*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 41},
                    "EndPosition": {"Line": 1, "Column": 145},
                }
            ],
            "MissingContextValues": [],
            "EvalDecisionDetails": {},
            "ResourceSpecificResults": [
                {
                    "EvalResourceName": "arn:aws:s3:::smoketurner-test-iam-bucket/*",
                    "EvalResourceDecision": "allowed",
                    "MatchedStatements": [
                        {
                            "SourcePolicyId": "PolicyInputList.1",
                            "SourcePolicyType": "IAM Policy",
                            "StartPosition": {"Line": 1, "Column": 41},
                            "EndPosition": {"Line": 1, "Column": 145},
                        }
                    ],
                    "MissingContextValues": [],
                }
            ],
        }
    ],
    "IsTruncated": False,
    "ResponseMetadata": {
        "RequestId": "5dd95549-3a65-418a-8861-46f5adbc9f0c",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "x-amzn-requestid": "5dd95549-3a65-418a-8861-46f5adbc9f0c",
            "content-type": "text/xml",
            "content-length": "1919",
            "date": "Mon, 02 Mar 2020 20:23:30 GMT",
        },
        "RetryAttempts": 0,
    },
}

