# PresExch Utilities
"""Utilities for dif presentation exchange attachment."""
from model import (
    PresentationDefinition,
    InputDescriptors,
    Field,
    Filter,
    Constraints,
    Holder,
    SubmissionRequirements,
    ClaimFormat,
    Requirement,
    SchemaInputDescriptor,
    VCRecord,
    VerifiablePresentation,
    InputDescriptorMapping,
    PresentationSubmission
)
from model import (
    PresentationDefinitionSchema,
    InputDescriptorsSchema,
    FieldSchema,
    FilterSchema,
    ConstraintsSchema,
    HolderSchema,
    SubmissionRequirementsSchema,
    ClaimFormatSchema,
    RequirementSchema,
    SchemaInputDescriptorSchema,
    VerifiablePresentationSchema,
    InputDescriptorMappingSchema,
)
from typing import Sequence, Optional, Any
from dateutil.parser import parse as dateutil_parser
import pytz
from uuid import uuid4
import json
import datetime
from jsonpath_ng import jsonpath, parse
from testdata import (
    cred_json_list,
    pd_dict_list,
)

def to_requirement(sr: SubmissionRequirements, descriptors: Sequence[InputDescriptors]) -> Requirement:
    input_descriptors = []
    nested = []
    total_count = 0

    if sr._from:
        if sr._from != "":
            for tmp_descriptor in descriptors:
                if contains(tmp_descriptor.groups, sr._from):
                    input_descriptors.append(tmp_descriptor)
            total_count = len(input_descriptors)
            if total_count == 0:
                raise Exception(
                    f"No descriptors for from: {sr._from}"
                )
    else:
        for tmp_sub_req in sr.from_nested:
            try:
                # recursion logic
                tmp_req = to_requirement(tmp_sub_req, descriptors)
                nested.append(tmp_req)
            except Exception as err:
                print(f"Error creating requirement from nested submission_requirements, {err}")
        total_count = len(nested)
    count = sr.count
    if sr.rule == "all":
        count = total_count

    requirement = Requirement(count=count, maximum=sr.maximum, minimum=sr.minimum, input_descriptors=input_descriptors, nested_req=nested)
    return requirement    

def make_requirement(sr: Sequence[SubmissionRequirements], descriptors: Sequence[InputDescriptors]) -> Requirement:
    if not sr:
        sr=[]
    if not descriptors:
        descriptors=[]
    if len(sr)==0:
        requirement = Requirement(
            count=len(descriptors),
            input_descriptors=descriptors,
        )
        return requirement
    requirement = Requirement(
        count=len(sr),
        nested_req=[],    
    )
    for tmp_sub_req in sr:
        try:
            requirement.nested_req.append(to_requirement(tmp_sub_req, descriptors))
        except Exception as err:
            print(f"Error creating requirement inside to_requirement function, {err}")

    return requirement

def is_len_applicable(req: Requirement, val: int) -> bool:
    if req.count:
        if req.count > 0 and val != req.count:
            return False
    if req.minimum:
        if req.minimum > 0 and req.minimum > val:
            return False
    if req.maximum:
        if req.maximum > 0 and req.maximum < val:
            return False
    return True

def contains(data: Sequence[str], e: str) -> bool:
    data_list = list(data) if data else []
    for tmp_item in data_list:
        if e == tmp_item:
            return True
    return False

def filter_constraints(constraints: Constraints, credentials: Sequence[VCRecord]) -> Sequence[VCRecord]:
    result = []
    for tmp_cred in credentials:
        if (
            constraints.subject_issuer != None and 
            constraints.subject_issuer == "required" and 
            not subject_is_issuer(credential=tmp_cred)
        ):
            continue
        
        applicable = False
        predicate = False
        for tmp_field in constraints._fields:
            applicable = filter_by_field(tmp_field, tmp_cred)
            if tmp_field.predicate and tmp_field.predicate:
                if tmp_field.predicate == "required":
                    predicate = True
            if applicable:
                break
        if not applicable:
            continue

        # TODO: create new credential with selective disclosure
        if constraints.limit_disclosure or predicate:
            raise "Not yet implemented - createNewCredential"

        result.append(tmp_cred)
    return result

def filter_by_field(field: Field, credential: VCRecord) -> bool:
    for tmp_path in field.paths:
        tmp_jsonpath = parse(tmp_path)
        match = tmp_jsonpath.find(json.loads(credential.value))
        if len(match) == 0:
            continue
        for match_item in match:
            if validate_patch(match_item.value, field._filter):
                return True
    return False
            
def validate_patch(to_check: any, _filter: Filter) -> bool:
    return_val = None
    if _filter._type:
        if _filter._type == "number":
            return_val = process_numeric_val(to_check, _filter)
        elif _filter._type == "string":
            return_val = process_string_val(str(to_check), _filter)
    else:
        if _filter.enums:                    
            return_val = enum_check(val=to_check, filter=_filter)
        if _filter.const:
            return_val = const_check(val=to_check, filter=_filter)

    if _filter._not:
        return not return_val
    else:
        return return_val

def process_numeric_val(val: any, _filter: Filter) -> bool:
    if _filter.exclusive_max:
        return exclusive_maximum_check(val, _filter)
    elif _filter.exclusive_min:
        return exclusive_minimum_check(val, _filter)
    elif _filter.minimum:
        return minimum_check(val, _filter)
    elif _filter.maximum:
        return maximum_check(val, _filter)
    elif _filter.const:
        return const_check(val, _filter)
    elif _filter.enums:
        return enum_check(val, _filter)
    else:
        return False


def process_string_val(val: str, _filter: Filter) -> bool:
    if _filter.min_length or _filter.max_length:
        return length_check(val, _filter)
    elif _filter.pattern:
        return pattern_check(val, _filter)
    elif _filter.enums:
        return enum_check(val, _filter)
    elif _filter.exclusive_max:
        if _filter.fmt:
            return exclusive_maximum_check(val, _filter)
    elif _filter.exclusive_min:
        if _filter.fmt:
            return exclusive_minimum_check(val, _filter)
    elif _filter.minimum:
        if _filter.fmt:
            return minimum_check(val, _filter)
    elif _filter.maximum:
        if _filter.fmt:
            return maximum_check(val, _filter)         
    elif _filter.const:
        return const_check(val, _filter)
    else:
        return False

def exclusive_minimum_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter.fmt:
            utc=pytz.UTC
            if _filter.fmt=="date" or _filter.fmt=="date-time":
                tmp_date = dateutil_parser(str(_filter.exclusive_min)).replace(tzinfo=utc)
                val = dateutil_parser(str(val)).replace(tzinfo=utc)
                return val > tmp_date
        elif _filter._type=="number":
            if type(val) is str:
                if val.isnumeric():
                    return float(val) > int(_filter.exclusive_min)
            else:
                return val > int(_filter.exclusive_min)
        return False
    except ValueError:
        return False

def exclusive_maximum_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter.fmt:
            utc=pytz.UTC
            if _filter.fmt=="date" or _filter.fmt=="date-time":
                tmp_date = dateutil_parser(str(_filter.exclusive_max)).replace(tzinfo=utc)
                val = dateutil_parser(str(val)).replace(tzinfo=utc)
                return val < tmp_date
        elif _filter._type=="number":
            if type(val) is str:
                if val.isnumeric():
                    return float(val) < int(_filter.exclusive_max)
            else:
                return val < int(_filter.exclusive_max)
        return False
    except ValueError:
        return False

def maximum_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter.fmt:
            utc=pytz.UTC
            if _filter.fmt=="date" or _filter.fmt=="date-time":
                tmp_date = dateutil_parser(str(_filter.maximum)).replace(tzinfo=utc)
                val = dateutil_parser(str(val)).replace(tzinfo=utc)
                return val <= tmp_date
        elif _filter._type=="number":
            if type(val) is str:
                if val.isnumeric():
                    return float(val) <= int(_filter.maximum)
            else:
                return val <= int(_filter.maximum)
        return False
    except ValueError:
        return False

def minimum_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter.fmt:
            utc=pytz.UTC
            if _filter.fmt=="date" or _filter.fmt=="date-time":
                tmp_date = dateutil_parser(str(_filter.minimum)).replace(tzinfo=utc)
                val = dateutil_parser(str(val)).replace(tzinfo=utc)
                return val >= tmp_date
        elif _filter._type=="number":
            if type(val) is str:
                if val.isnumeric():
                    return float(val) >= int(_filter.minimum)
            else:
                return val >= int(_filter.minimum)
        return False
    except ValueError:
        return False

def length_check(val: str, _filter: Filter) -> bool:
    given_len = len(val)
    if _filter.max_length and _filter.min_length:
        if given_len <= _filter.max_length and given_len >= _filter.min_length:
            return True
    elif _filter.max_length and not _filter.min_length:
        if given_len <= _filter.max_length:
            return True
    elif not _filter.max_length and _filter.min_length:
        if given_len >= _filter.min_length:
            return True
    return False

def pattern_check(val: str, _filter: Filter) -> bool:
    if _filter.pattern:
        to_check = _filter.pattern.split('|')
        if val in to_check:
            return True
    return False


def const_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter._type:
            if _filter._type == "number":
                if int(val) == int(_filter.const):
                    return True
            elif _filter._type == "string":
                if str(val) == _filter.const:
                    return True
        else:
            if type(val) is int:
                if val == int(_filter.const):
                    return True
            else:
                if val == _filter.const:
                    return True
        return False
    except ValueError:
        return False

def enum_check(val: any, _filter: Filter) -> bool:
    if _filter._type:
        if _filter._type=="number":
            for tmp in _filter.enums:
                try:
                    if int(val) == int(tmp):
                        return True
                except ValueError:
                    continue
        elif _filter._type=="string":
            if str(val) in _filter.enums:
                return True
    else:
        if type(val) is int:
            for tmp in _filter.enums:
                try:
                    if int(val) == int(tmp):
                        return True
                except ValueError:
                    continue
        else:
            if str(val) in _filter.enums:
                return True
    return False

def subject_is_issuer(credential: VCRecord) -> bool:
    subject_ids = credential.subject_ids
    for tmp_subject_id in subject_ids:
        tmp_issuer = credential.issuer
        tmp_issuer_id = tmp_issuer._id
        if tmp_subject_id != "" and tmp_subject_id == tmp_issuer_id:
            return True
    return False


def filter_schema(credentials: Sequence[VCRecord], schemas: Sequence[SchemaInputDescriptor]) -> Sequence[VCRecord]:
    result = []
    for tmp_cred in credentials:
        applicable = False
        for tmp_schema in schemas:
            applicable = credential_match_schama(credential=tmp_cred, schema_id=tmp_schema.uri)
            if tmp_schema.required and not applicable:
                break
        if applicable:
            result.append(tmp_cred)
    return result

def credential_match_schama(credential: VCRecord, schema_id: str) -> bool:
    if "schema_ids" in credential.tags:
        for cred_schema_id in credential.tags.get("schema_ids"):
            if cred_schema_id == schema_id:
                return True
    return False

def apply_requirements(req: Requirement, credentials: Sequence[VCRecord]) -> dict:
    # map of input_descriptor ID key to list of credential_json
    result = {}
    descriptor_list = []
    if not req.input_descriptors:
        descriptor_list = []
    else:
        descriptor_list = req.input_descriptors
    for tmp_descriptor in descriptor_list:
        filtered_by_schema = filter_schema(credentials=credentials, schemas=tmp_descriptor.schemas)
        filtered = filter_constraints(constraints=tmp_descriptor.constraint, credentials=filtered_by_schema)
        if len(filtered) != 0:
            result[tmp_descriptor._id] = filtered

    if len(descriptor_list) != 0:
        if is_len_applicable(req, len(result)):
            return result
        return {}

    nested_result = []
    tmp_dict = {}
    # recursion logic for nested requirements
    for tmp_req in req.nested_req:
        tmp_result = apply_requirements(tmp_req, credentials)
        if tmp_result == {}:
            continue

        for tmp_desc_id in tmp_result.keys():
            tmp_creds_list = tmp_result.get(tmp_desc_id)
            for tmp_cred in tmp_creds_list:
                if trim_tmp_id(tmp_cred.given_id) not in tmp_dict:
                    tmp_dict[trim_tmp_id(tmp_cred.given_id)] = {}
                tmp_dict[trim_tmp_id(tmp_cred.given_id)][tmp_desc_id] = tmp_cred.given_id

        if len(tmp_result.keys()) != 0:
            nested_result.append(tmp_result)

    exclude = {}
    for k in tmp_dict.keys():
        if not is_len_applicable(req, len(tmp_dict[k])):
            for desc_id in tmp_dict[k]:
                exclude[desc_id+(tmp_dict[k][desc_id])] = {}

    return merge_nested_results(nested_result=nested_result, exclude=exclude)

def get_tmp_id(id: str) -> str:
    return id + "tmp_unique_id_" + str(uuid4())

def trim_tmp_id(id: str) -> str:
    try: 
        tmp_index = id.index("tmp_unique_id_")
        return id[:tmp_index]
    except ValueError:
        return id

def merge_nested_results(nested_result: Sequence[dict], exclude: dict) -> dict:
    result = {}
    for res in nested_result:
        for key in res.keys():
            credentials = res[key]
            tmp_dict = {}
            merged_credentials = []
            
            if key in result:
                for tmp_cred in result[key]:
                    if tmp_cred.given_id not in tmp_dict:
                        merged_credentials.append(tmp_cred)
                        tmp_dict[tmp_cred.given_id] = {}

            for tmp_cred in credentials:
                if tmp_cred.given_id not in tmp_dict:
                    if (key+(tmp_cred.given_id)) not in exclude:
                        merged_credentials.append(tmp_cred)
                        tmp_dict[tmp_cred.given_id] = {}
            result[key] = merged_credentials
    return result

def create_vp(credentials: Sequence[VCRecord], pd: PresentationDefinition) -> Optional[VerifiablePresentation]:
    req = make_requirement(sr=pd.submission_requirements, descriptors=pd.input_descriptors)
    result = apply_requirements(req=req, credentials=credentials)
    applicable_creds, descriptor_maps = merge(result)
    # convert list of verifiable credentials to list to dict
    applicable_cred_dict = []
    for tmp_cred in applicable_creds:
        applicable_cred_dict.append(json.loads(tmp_cred.value))
    # submission_property
    submission_property = PresentationSubmission(
        _id=str(uuid4()),
        definition_id=pd._id,
        descriptor_maps=descriptor_maps
    )

    # defaultVPContext
    default_vp_context = [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/presentation-exchange/submission/v1",
    ]
    # defaultVPType
    default_vp_type = [
        "VerifiablePresentation",
        "PresentationSubmission",
    ]

    vp = VerifiablePresentation(
        _id=str(uuid4()),
        contexts=default_vp_context,
        types=default_vp_type,
        credentials=applicable_cred_dict,
        presentation_submission=submission_property,
    )
    return vp

def merge(dict_descriptor_creds: dict) -> (Sequence[VCRecord], Sequence[InputDescriptorMapping]):
    dict_of_creds = {}
    dict_of_descriptors = {}
    result = []
    descriptors = []
    sorted_desc_keys = sorted(list(dict_descriptor_creds.keys()))
    for desc_id in sorted_desc_keys:
        credentials = dict_descriptor_creds.get(desc_id)
        for tmp_cred in credentials:
            if tmp_cred.given_id not in dict_of_creds:
                result.append(tmp_cred)
                dict_of_creds[trim_tmp_id(tmp_cred.given_id)] = len(descriptors)

            if f"{tmp_cred.given_id}-{tmp_cred.given_id}" not in dict_of_descriptors:
                descriptor_map = InputDescriptorMapping(_id=desc_id,fmt="ldp_vp", path=f"$.verifiableCredential[{dict_of_creds[tmp_cred.given_id]}]")
                descriptors.append(descriptor_map)

    descriptors = sorted(descriptors, key = lambda i: i._id)
    return (result, descriptors)

# Test
def test():
    all_cred = []
    for tmp_cred_json in cred_json_list:
        all_cred.append(VCRecord.deserialize(tmp_cred_json))
    for index in range(len(pd_dict_list)):
        tmp_pd = PresentationDefinitionSchema().load(pd_dict_list[index])
        tmp_vp = create_vp(credentials=all_cred, pd=tmp_pd)
        if tmp_vp:
            print(json.dumps(VerifiablePresentationSchema().dump(tmp_vp)))

if __name__ == "__main__":
    test()

