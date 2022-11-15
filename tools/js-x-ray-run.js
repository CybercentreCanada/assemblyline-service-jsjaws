import { runASTAnalysis } from "@nodesecure/js-x-ray";
import { readFileSync } from "fs";

var file_path = process.argv[2];
const str = readFileSync(file_path, "utf-8");
const { warnings } = runASTAnalysis(str);
console.log(JSON.stringify({"warnings": warnings}));
