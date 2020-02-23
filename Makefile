setup:
	python3 -m venv .venv
	.venv/bin/pip3 install -r requirements.txt
	.venv/bin/pip3 install -r src/handlers/create_role/requirements.txt
	.venv/bin/pip3 install -r src/handlers/evaluate_policy/requirements.txt
	.venv/bin/pip3 install -r src/handlers/verify_role/requirements.txt

build:
	sam build -u

deploy:
	sam deploy

format:
	black .

test:
	bash run_tests.sh

invoke:
	./generate_event.js
	sam local invoke "EvaluatePolicyLambdaFunction" -e event.json

list-policies:
	aws iam list-policies --profile jplock --output text | awk '{print $2}' | grep FullAccess | sort
