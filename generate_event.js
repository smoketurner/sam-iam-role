#!/usr/bin/env node

const fs = require("fs");

const roles = fs.readFileSync("./sample_roles.yml", "utf8");

const event = {
  type: "iam",
  account_id: "1234567",
  stack_name: "EksCluster",
  roles
};

const data = JSON.stringify(event, null, 2);

fs.writeFileSync("./event.json", data, "utf8");
