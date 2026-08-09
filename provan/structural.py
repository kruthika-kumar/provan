from __future__ import annotations

import re
from typing import Any


class StructuralValidationError(ValueError):
    def __init__(self,path: tuple[str|int,...],keyword: str):
        self.path=path;self.keyword=keyword
        super().__init__(f"{keyword} at /"+"/".join(map(str,path)))


def _matches_type(value: Any, expected: str) -> bool:
    if expected=="object":return isinstance(value,dict)
    if expected=="array":return isinstance(value,list)
    if expected=="string":return isinstance(value,str)
    if expected=="integer":return isinstance(value,int) and not isinstance(value,bool)
    if expected=="number":return isinstance(value,(int,float)) and not isinstance(value,bool)
    if expected=="boolean":return isinstance(value,bool)
    if expected=="null":return value is None
    return False


def validate_schema_instance(value: Any,schema: dict[str,Any],path: tuple[str|int,...]=()) -> None:
    if "const" in schema and value!=schema["const"]:raise StructuralValidationError(path,"const")
    if "enum" in schema and value not in schema["enum"]:raise StructuralValidationError(path,"enum")
    expected=schema.get("type")
    if expected is not None:
        options=[expected] if isinstance(expected,str) else expected
        if not any(_matches_type(value,item) for item in options):raise StructuralValidationError(path,"type")
    if isinstance(value,dict):
        missing=set(schema.get("required",[]))-set(value)
        if missing:raise StructuralValidationError(path,"required")
        if len(value)<schema.get("minProperties",0):raise StructuralValidationError(path,"minProperties")
        properties=schema.get("properties",{});additional=schema.get("additionalProperties",True)
        for key,item in value.items():
            if key in properties:validate_schema_instance(item,properties[key],path+(key,))
            elif additional is False:raise StructuralValidationError(path+(key,),"additionalProperties")
            elif isinstance(additional,dict):validate_schema_instance(item,additional,path+(key,))
    if isinstance(value,list):
        if len(value)<schema.get("minItems",0):raise StructuralValidationError(path,"minItems")
        if "maxItems" in schema and len(value)>schema["maxItems"]:raise StructuralValidationError(path,"maxItems")
        if isinstance(schema.get("items"),dict):
            for index,item in enumerate(value):validate_schema_instance(item,schema["items"],path+(index,))
    if isinstance(value,str):
        if len(value)<schema.get("minLength",0):raise StructuralValidationError(path,"minLength")
        if "pattern" in schema and re.fullmatch(schema["pattern"],value) is None:raise StructuralValidationError(path,"pattern")
    if isinstance(value,(int,float)) and not isinstance(value,bool):
        if "minimum" in schema and value<schema["minimum"]:raise StructuralValidationError(path,"minimum")
        if "maximum" in schema and value>schema["maximum"]:raise StructuralValidationError(path,"maximum")
