// Test file for no-packagejson-import rule

// This should trigger high severity
import * as pkg from "~/package.json";

// This should also trigger
import packageInfo from "../package.json";

// This should trigger warn severity
const version = require("./package.json").version;

// This is safe - not package.json
import { something } from "./other-module";

// Using the imported values
console.log(pkg.version);
console.log(packageInfo.name);

export function getVersion() {
  return version;
}
