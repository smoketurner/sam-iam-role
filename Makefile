setup:
	python3 -m venv .venv
	source .venv/bin/activate.csh
	pip3 install -r requirements.txt

build:
	sam build -u

deploy:
	sam deploy

format:
	black .

test:
	python3 -m unittest discover -s src/handlers

invoke:
	sam local invoke "EvaluatePolicyLambdaFunction"

list-policies:
	aws iam list-policies --profile jplock --output text | awk '{print $2}' | grep FullAccess | sort
