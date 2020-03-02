#!/usr/bin/env node

const fs = require("fs");

const roles = fs.readFileSync("./sample_roles.yml", "utf8");

const event = {
  type: "iam",
  account_id: "194184563732",
  region: "us-east-1",
  stack_name: "PlaydateRoles",
  roles
};

const data = JSON.stringify(event, null, 2);

fs.writeFileSync("./event.json", data, "utf8");
