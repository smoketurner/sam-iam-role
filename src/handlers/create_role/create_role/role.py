class Role:
    role_dict = None
    policies = []

    def __init__(self, role_dict):
        self.role_dict = role_dict
        self.policies = []

    def to_cf_json(self, whitespace=False) -> str:
        assume_statement = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {},
        }

        settings = self.role_dict["settings"]

        principal_service = settings.get("principal_service", [])
        if not isinstance(principal_service, list):
            principal_service = [principal_service]

        if principal_service:
            assume_statement["Principal"]["Service"] = [
                principal + ".amazonaws.com" for principal in principal_service
            ]

        if "principal_aws" in settings:
            assume_statement["Principal"]["AWS"] = settings["principal_aws"]
        if "principal_canonical_user" in settings:
            assume_statement["Principal"]["CanonicalUser"] = settings[
                "principal_canonical_user"
            ]
        if "principal_federated" in settings:
            assume_statement["Principal"]["Federated"] = settings["principal_federated"]

        role = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [assume_statement],
                },
                "Description": {
                    "Fn::Sub": "DO NOT DELETE - Created by Role Creation Service. Created by CloudFormation ${AWS::StackId}"
                },
                "Path": "/rcs/",
                "RoleName": self.role_dict["name"],
            },
        }

        if self.policies:
            role["Properties"]["Policies"] = self.policies
        if self.managed_policy_arns:
            role["Properties"]["ManagedPolicyArns"] = [
                {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/" + policy}
                for policy in self.managed_policy_arns
            ]

        if whitespace:
            params = {"indent": 2, "sort_keys": True, "separators": (", ", ": ")}
        else:
            params = {"indent": None, "sort_keys": True, "separators": (",", ":")}

        return json.dumps(role, **params)
