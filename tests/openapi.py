"""Validate the public contract and its examples, without accessing mail services."""
import json
from pathlib import Path
import warnings

from openapi_spec_validator import validate
from openapi_schema_validator import OAS30Validator

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from jsonschema import RefResolver

root = Path(__file__).resolve().parent.parent
spec = json.loads((root / "public/openapi.json").read_text())
validate(spec)
operation = spec["paths"]["/"]["post"]
resolver = RefResolver.from_schema(spec)
request = operation["requestBody"]["content"]["application/json"]
request_validator = OAS30Validator(request["schema"], resolver=resolver)
for example in request["examples"].values():
    request_validator.validate(example["value"])
for response in operation["responses"].values():
    content = response["content"]["application/json"]
    validator = OAS30Validator(content["schema"], resolver=resolver)
    for example in content.get("examples", {}).values():
        validator.validate(example["value"])
    if "example" in content:
        validator.validate(content["example"])
print("OpenAPI specification and all request/response examples are valid.")
