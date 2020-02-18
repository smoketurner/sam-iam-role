[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/smoketurner/sam-org/master/LICENSE)
[![build status](https://github.com/smoketurner/sam-org/workflows/Node%20CI/badge.svg)](https://github.com/smoketurner/sam-org/actions?query=workflow%3A%22Node+CI%22)
[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/lambda/home?#/create/app?applicationId=arn:aws:serverlessrepo:us-east-1:860114833029:applications/cloudfront-cdn)

[AWS Serverless Application Model](https://aws.amazon.com/serverless/sam/) project that deploys and AWS account creation API an an IAM role creation API.

## Installation

```
git clone https://github.com/smoketurner/sam-org.git
cd sam-org
npm install
```

## Run Tests

```
npm test
```

## Deploy

```
npm run build
npm run deploy
```

## References

- https://www.youtube.com/watch?v=70zvdxE1DPk
