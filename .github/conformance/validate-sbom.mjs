import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import addFormats2019 from "ajv-formats-draft2019";

if (process.argv.length !== 4) {
  console.error("Usage: node validate-sbom.mjs <CycloneDX-schema-directory> <bom.cdx.json>");
  process.exit(2);
}

const schemaDirectory = process.argv[2];
const bomPath = process.argv[3];
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const schema = readJson(path.join(schemaDirectory, "bom-1.6.schema.json"));
const spdx = readJson(path.join(schemaDirectory, "spdx.schema.json"));
const jsf = readJson(path.join(schemaDirectory, "jsf-0.82.schema.json"));
const bom = readJson(bomPath);

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
addFormats2019(ajv);
ajv.addSchema(spdx);
ajv.addSchema(jsf);
const validate = ajv.compile(schema);
if (!validate(bom)) {
  console.error(ajv.errorsText(validate.errors, { separator: "\n" }));
  process.exit(1);
}
console.log(`CycloneDX 1.6 schema validation passed: ${bomPath}`);
