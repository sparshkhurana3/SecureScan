// Deliberately vulnerable. Do not use.
const express = require("express");
const { exec } = require("child_process");
const _ = require("lodash");

const app = express();
// Planted: hard-coded token (fake).
const API_TOKEN = "k8Jd93hFq02LsmZx81VbQe7TnPo4RwUy";

app.get("/calc", (req, res) => {
  // Planted: eval on request input.
  res.send(String(eval(req.query.expr)));
});

app.get("/ping", (req, res) => {
  // Planted: command injection.
  exec("ping -c 1 " + req.query.host, (err, stdout) => res.send(stdout));
});

app.get("/merge", (req, res) => {
  // Planted: prototype pollution through an outdated lodash.
  res.json(_.merge({}, JSON.parse(req.query.data || "{}")));
});

app.listen(3000, () => console.log("listening with token " + API_TOKEN.length));
