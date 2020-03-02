response = {
    "EvaluationResults": [
        {
            "EvalActionName": "s3:GetObject",
            "EvalResourceName": "arn:aws:s3:::smoketurner-test-iam-bucket",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "PolicyInputList.1",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": {"Line": 1, "Column": 41},
                    "EndPosition": {"Line": 1, "Column": 143},
                }
            ],
            "MissingContextValues": [],
            "EvalDecisionDetails": {},
            "ResourceSpecificResults": [
                {
                    "EvalResourceName": "arn:aws:s3:::smoketurner-test-iam-bucket",
                    "EvalResourceDecision": "allowed",
                    "MatchedStatements": [
                        {
                            "SourcePolicyId": "PolicyInputList.1",
                            "SourcePolicyType": "IAM Policy",
                            "StartPosition": {"Line": 1, "Column": 41},
                            "EndPosition": {"Line": 1, "Column": 143},
                        }
                    ],
                    "MissingContextValues": [],
                }
            ],
        }
    ],
    "IsTruncated": False,
    "ResponseMetadata": {
        "RequestId": "e493361b-2187-436f-b593-37cac59ad7f3",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "x-amzn-requestid": "e493361b-2187-436f-b593-37cac59ad7f3",
            "content-type": "text/xml",
            "content-length": "1915",
            "date": "Sun, 01 Mar 2020 21:53:53 GMT",
        },
        "RetryAttempts": 0,
    },
}

