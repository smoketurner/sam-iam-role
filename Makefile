build:
	sam build -u

deploy:
	sam deploy

format:
	black .

invoke:
	sam local invoke "EvaluatePolicyLambdaFunction"

list-policies:
	aws iam list-policies --profile jplock --output text | awk '{print $2}' | grep FullAccess | sort
