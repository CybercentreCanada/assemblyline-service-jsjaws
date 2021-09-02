const { runASTAnalysis } = require("js-x-ray");
const { readFileSync } = require("fs");

var argv = require('minimist')(process.argv.slice(2), {
    "boolean": true
});
file_path = argv._[0];

const str = readFileSync(file_path, "utf-8");
const { warnings } = runASTAnalysis(str);
console.log(JSON.stringify({"warnings": warnings}));