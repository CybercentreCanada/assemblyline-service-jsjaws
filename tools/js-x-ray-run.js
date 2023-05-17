import { runASTAnalysis } from "@nodesecure/js-x-ray";
import { readFileSync } from "fs";

const dividing_comment = process.argv[2];
const file_path = process.argv[3];

const file_contents = readFileSync(file_path, "utf-8");

// Splitting on an obvious differentiator from the code that dynamically creates elements and the original script
const split_script = file_contents.split(dividing_comment)
if (split_script.length == 2) {
    var actual_script = split_script[1];
} else {
    var actual_script = split_script[0];
}

const options = { "removeHTMLComments": true };
const { warnings } = runASTAnalysis(actual_script, options);
console.log(JSON.stringify({"warnings": warnings}));
