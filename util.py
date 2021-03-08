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
    VerifiableCredential,
    VerifiablePresentation,
    InputDescriptorMapping,
    Issuer,
    TypedID,
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
    VerifiableCredentialSchema,
    VerifiablePresentationSchema,
    InputDescriptorMappingSchema,
)
from typing import Sequence, Optional, Any
from dateutil.parser import parse
import pytz
import uuid
import json
import datetime
from jsonpath_ng import jsonpath, parse
from testdata import (
    vc_dict_list,
    pd_dict_list,
)

def to_requirement(sr: SubmissionRequirements, descriptors: Sequence[InputDescriptors]) -> Requirement:
    input_descriptors = []
    nested = []
    total_count = 0

    if sr._from != "":
        for tmp_descriptor in descriptors:
            if contains(tmp_descriptor.group, sr._from):
                input_descriptors.append(tmp_descriptor)
        total_count = len(input_descriptors)
        if total_count == 0:
            raise Exception(
                f"No descriptors for from: {sr._from}"
            )
    else:
        for tmp_sub_req in sr._from_nested:
            try:
                # recursion logic
                tmp_req = to_requirement(tmp_sub_req, descriptors)
                nested.append(tmp_req)
            except Exception:
                print(f"Error creating requirement from nested submission_requirements")
        total_count = len(nested)
    count = sr.count
    if sr.rule == "all":
        count = total_count

    requirement = Requirement(count=count, maximum=sr.maximum, minimum=sr.minimum, _input_descriptors=input_descriptors, _nested_req=nested)
    return requirement    

def make_requirement(sr: Sequence[SubmissionRequirements], descriptors: Sequence[InputDescriptors]) -> Requirement:
    if not sr:
        sr=[]
    if not descriptors:
        descriptors=[]
    if len(sr)==0:
        requirement = Requirement(
            count=len(descriptors),
            _input_descriptors=descriptors,
        )
        return requirement
    requirement = Requirement(
        count=len(sr),
        _nested_req=[],    
    )
    for tmp_sub_req in sr:
        try:
            requirement._nested_req.append(to_requirement(tmp_sub_req, descriptors))
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

def filter_constraints(constraints: Constraints, credentials: Sequence[VerifiableCredential]) -> Sequence[VerifiableCredential]:
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

def filter_by_field(field: Field, credential: VerifiableCredential) -> bool:
    for tmp_path in field.path:
        tmp_jsonpath = parse(tmp_path)
        # match = tmp_jsonpath.find(credential.serialize())
        match = tmp_jsonpath.find(credential.provided_cred_json)
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
        if _filter._enum:                    
            return_val = enum_check(val=to_check, filter=_filter)
        if _filter.const:
            return_val = const_check(val=to_check, filter=_filter)

    if _filter._not is True and return_val:
        return not return_val
    elif return_val:
        return return_val
    else:
        return False

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
    elif _filter._enum:
        return enum_check(val, _filter)
    else:
        return False


def process_string_val(val: str, _filter: Filter) -> bool:
    if _filter.min_length or _filter.max_length:
        return length_check(val, _filter)
    elif _filter.pattern:
        return pattern_check(val, _filter)
    elif _filter._enum:
        return enum_check(val, _filter)
    elif _filter.exclusive_max:
        if _filter._format:
            return exclusive_maximum_check(val, _filter)
    elif _filter.exclusive_min:
        if _filter._format:
            return exclusive_minimum_check(val, _filter)
    elif _filter.minimum:
        if _filter._format:
            return minimum_check(val, _filter)
    elif _filter.maximum:
        if _filter._format:
            return maximum_check(val, _filter)         
    elif _filter.const:
        return const_check(val, _filter)
    else:
        return False

def exclusive_minimum_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter._format:
            utc=pytz.UTC
            if _filter._format=="date" or _filter._format=="date-time":
                tmp_date = parse(str(_filter.exclusive_min)).replace(tzinfo=utc)
                val = parse(str(val)).replace(tzinfo=utc)
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
        if _filter._format:
            utc=pytz.UTC
            if _filter._format=="date" or _filter._format=="date-time":
                tmp_date = parse(str(_filter.exclusive_min)).replace(tzinfo=utc)
                val = parse(str(val)).replace(tzinfo=utc)
                return val < tmp_date
        elif _filter._type=="number":
            if type(val) is str:
                if val.isnumeric():
                    return float(val) < int(_filter.exclusive_min)
            else:
                return val < int(_filter.exclusive_min)
        return False
    except ValueError:
        return False

def maximum_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter._format:
            utc=pytz.UTC
            if _filter._format=="date" or _filter._format=="date-time":
                tmp_date = parse(str(_filter.exclusive_min)).replace(tzinfo=utc)
                val = parse(str(val)).replace(tzinfo=utc)
                return val <= tmp_date
        elif _filter._type=="number":
            if type(val) is str:
                if val.isnumeric():
                    return float(val) <= int(_filter.exclusive_min)
            else:
                return val <= int(_filter.exclusive_min)
        return False
    except ValueError:
        return False

def minimum_check(val: any, _filter: Filter) -> bool:
    try:
        if _filter._format:
            utc=pytz.UTC
            if _filter._format=="date" or _filter._format=="date-time":
                tmp_date = parse(str(_filter.exclusive_min)).replace(tzinfo=utc)
                val = parse(str(val)).replace(tzinfo=utc)
                return val >= tmp_date
        elif _filter._type=="number":
            if type(val) is str:
                if val.isnumeric():
                    return float(val) >= int(_filter.exclusive_min)
            else:
                return val >= int(_filter.exclusive_min)
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
            for tmp in _filter._enum:
                try:
                    if int(val) == int(tmp):
                        return True
                except ValueError:
                    continue
        elif _filter._type=="string":
            if str(val) in _filter._enum:
                return True
    else:
        if type(val) is int:
            for tmp in _filter._enum:
                try:
                    if int(val) == int(tmp):
                        return True
                except ValueError:
                    continue
        else:
            if str(val) in _filter._enum:
                return True
    return False

def subject_is_issuer(credential: VerifiableCredential) -> bool:
    subject_ids = get_subject_ids(cred_subject=credential.subject)
    for tmp_subject_id in subject_ids:
        tmp_issuer = credential.issuer
        tmp_issuer_id = tmp_issuer._id
        if tmp_subject_id != "" and tmp_subject_id == tmp_issuer_id:
            return True
    return False

def get_subject_ids(cred_subject: Any) -> Sequence[str]:
    subject_ids = []
    if isinstance(cred_subject, str):
        subject_ids.append(cred_subject)
    elif isinstance(cred_subject, dict):
        tmp_subject_id = cred_subject.get("id") or None
        if tmp_subject_id:
            subject_ids.append(str(tmp_subject_id))
    elif (
        isinstance(cred_subject, list) or
        isinstance(cred_subject, Sequence)
    ):
        for tmp_cred_sub_dict in cred_subject:
            tmp_subject_id = tmp_cred_sub_dict.get("id") or None
            if tmp_subject_id:
                subject_ids.append(str(tmp_subject_id))
    return subject_ids

def filter_schema(credentials: Sequence[VerifiableCredential], schemas: Sequence[SchemaInputDescriptor]) -> Sequence[VerifiableCredential]:
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

def credential_match_schama(credential: VerifiableCredential, schema_id: str) -> bool:
    if credential.schemas:
        for cred_schema in credential.schemas:
            if cred_schema._id == schema_id:
                return True
    return False

def apply_requirements(req: Requirement, credentials: Sequence[VerifiableCredential]) -> dict:
    # map of input_descriptor ID key to list of credential_json
    result = {}
    descriptor_list = []
    if not req._input_descriptors:
        descriptor_list = []
    else:
        descriptor_list = req._input_descriptors
    for tmp_descriptor in descriptor_list:
        filtered_by_schema = filter_schema(credentials=credentials, schemas=tmp_descriptor._schema)
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
    for tmp_req in req._nested_req:
        tmp_result = apply_requirements(tmp_req, credentials)
        if tmp_result == {}:
            continue

        for tmp_desc_id in tmp_result.keys():
            tmp_creds_list = tmp_result.get(tmp_desc_id)
            for tmp_cred in tmp_creds_list:
                if trim_tmp_id(tmp_cred._id) not in tmp_dict:
                    tmp_dict[trim_tmp_id(tmp_cred._id)] = {}
                tmp_dict[trim_tmp_id(tmp_cred._id)][tmp_desc_id] = tmp_cred._id

        if len(tmp_result.keys()) != 0:
            nested_result.append(tmp_result)

    exclude = {}
    for k in tmp_dict.keys():
        if not is_len_applicable(req, len(tmp_dict[k])):
            for desc_id in tmp_dict[k]:
                exclude[desc_id+(tmp_dict[k][desc_id])] = {}

    return merge_nested_results(nested_result=nested_result, exclude=exclude)

def get_tmp_id(id: str) -> str:
    return id + "tmp_unique_id_" + str(uuid.uuid4())

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
                    if tmp_cred._id not in tmp_dict:
                        merged_credentials.append(tmp_cred)
                        tmp_dict[tmp_cred._id] = {}

            for tmp_cred in credentials:
                if tmp_cred._id not in tmp_dict:
                    if (key+(tmp_cred._id)) not in exclude:
                        merged_credentials.append(tmp_cred)
                        tmp_dict[tmp_cred._id] = {}
            result[key] = merged_credentials
    return result

def create_vp(credentials: Sequence[VerifiableCredential], pd: PresentationDefinition) -> Optional[VerifiablePresentation]:
    req = make_requirement(sr=pd.submission_requirements, descriptors=pd.input_descriptors)
    result = apply_requirements(req=req, credentials=credentials)
    applicable_creds, descriptor_map = merge(result)
    # convert list of verifiable credentials to list to dict
    applicable_cred_dict = []
    for tmp_cred in applicable_creds:
        # applicable_cred_dict.append(tmp_cred.serialize())
        applicable_cred_dict.append(VerifiableCredentialSchema().dump(tmp_cred))
    # submission_property
    submission_property = {
        "id": str(uuid.uuid4()),
        "definition_id": pd._id,
        "descriptor_map": descriptor_map, 
    }
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
        _id=str(uuid.uuid4()),
        context=default_vp_context,
        _types=default_vp_type,
        credentials=applicable_cred_dict,
        custom_field=submission_property,
    )
    return vp

def merge(dict_descriptor_creds: dict) -> (Sequence[VerifiableCredential], Sequence[InputDescriptorMapping]):
    dict_of_creds = {}
    dict_of_descriptors = {}
    result = []
    descriptors = []
    sorted_desc_keys = sorted(list(dict_descriptor_creds.keys()))
    for desc_id in sorted_desc_keys:
        credentials = dict_descriptor_creds.get(desc_id)
        for tmp_cred in credentials:
            if tmp_cred._id not in dict_of_creds:
                result.append(tmp_cred)
                dict_of_creds[trim_tmp_id(tmp_cred._id)] = len(descriptors)

            if f"{tmp_cred._id}-{tmp_cred._id}" in dict_of_descriptors:
                descriptor_map = InputDescriptorMapping(_id=desc_id,_format="ldp_vp", path=f"$.verifiableCredential[{dict_of_creds[tmp_cred._id]}]")
                descriptors.append(descriptor_map)

    descriptors = sorted(descriptors, key = lambda i: i._id)
    return (result, descriptors)

# Test
def test():
    all_cred = []
    for tmp_cred_dict in vc_dict_list:
        all_cred.append(to_vc(tmp_cred_dict))
    for index in range(len(pd_dict_list)):
        tmp_pd = to_pd(pd_dict_list[index])
        tmp_vp = create_vp(credentials=all_cred, pd=tmp_pd)
        if tmp_vp:
            print(to_vp_json(tmp_vp))
 
def to_vc(cred: dict) -> VerifiableCredential:
    proof_list = []
    refresh_service_list = []
    terms_of_service_list = []
    evidence_list = []
    schema_list = []
    if cred.get("proof"):
        if type(cred.get("proof")) is not list:
            proof_list.append(cred.get("proof"))
        else:
            proof_list = cred.get("proof")
    if cred.get("termsOfUse"):
        if type(cred.get("termsOfUse")) is not list:
            terms_of_service_list.append(cred.get("termsOfUse"))
        else:
            terms_of_service_list = cred.get("termsOfUse")
    if cred.get("refreshService"):
        if type(cred.get("refreshService")) is not list:
            refresh_service_list.append(cred.get("refreshService"))
        else:
            refresh_service_list = cred.get("refreshService")
    if cred.get("evidence"):
        if type(cred.get("evidence")) is not list:
            evidence_list.append(cred.get("evidence"))
        else:
            evidence_list = cred.get("evidence")
    if cred.get("credentialSchema"):
        tmp_schema_list = []
        if type(cred.get("credentialSchema")) is not list:
            tmp_schema_list.append(cred.get("credentialSchema"))
        else:
            tmp_schema_list = cred.get("credentialSchema")
        for tmp_schema in tmp_schema_list:
            schema_list.append(TypedID(_id=tmp_schema.get("id"), _type=tmp_schema.get("type")))

    if len(proof_list) == 0:
        proof_list = None
    if len(refresh_service_list) == 0:
        refresh_service_list = None
    if len(terms_of_service_list) == 0:
        terms_of_service_list = None
    if len(evidence_list) == 0:
        evidence_list = None        
    if len(schema_list) == 0:
        schema_list = None

    return VerifiableCredential(
        _id=cred.get("id"),
        context=cred.get("@context"),
        _types=cred.get("type"),
        subject=cred.get("credentialSubject"),
        issued=cred.get("issuanceDate"),
        expired=cred.get("expirationDate"),
        proofs=proof_list,
        evidence=evidence_list,
        status=cred.get("credentialStatus"),
        schemas=schema_list,
        terms_of_use=terms_of_service_list,
        refresh_service=refresh_service_list,
        issuer=Issuer(_id=cred.get("issuer")),
        provided_cred_json=cred,
    )

def to_vp_json(vp: VerifiablePresentation) -> str:
    tmp_dict = {}
    tmp_dict["@context"] = vp.context
    tmp_dict["type"] = vp._types
    tmp_dict["id"] = vp._id
    if vp.proofs:
        tmp_dict["proof"] = vp.proofs
    if vp.credentials:
        tmp_dict["verifiableCredential"] = vp.credentials
    else:
        tmp_dict["verifiableCredential"] = []
    if vp.holder:
        tmp_dict["holder"] = vp.holder 

    return json.dumps(tmp_dict)


def to_sr(sub_req: dict, nested_req: Sequence[SubmissionRequirements]=None) -> SubmissionRequirements:
    return SubmissionRequirements(
        name=sub_req.get("name"),
        purpose=sub_req.get("purpose"),
        rule=sub_req.get("rule"),
        count=sub_req.get("count"),
        minimum=sub_req.get("min"),
        maximum=sub_req.get("max"),
        _from=sub_req.get("from"),
        _from_nested=nested_req,
    )

def to_input_desc(descriptor: dict) -> InputDescriptors:
    constraint = None
    schema_list = []
    if descriptor.get("schema"):
        schema_list = to_input_desc_schema(descriptor)
    if descriptor.get("constraints"):
        constraint = to_constraint(descriptor.get("constraints"))
    
    return InputDescriptors(
        _id=descriptor.get("id"),
        group=descriptor.get("group"),
        name=descriptor.get("name"),
        purpose=descriptor.get("purpose"),
        constraint=constraint,
        _schema=schema_list,
    )

def to_constraint(tmp_constraint: dict) -> Constraints:
    tmp_limit_disclosure = tmp_constraint.get("limit_disclosure")
    tmp_subject_is_issuer = tmp_constraint.get("subject_is_issuer")

    holder_list = []
    field_list = []

    if tmp_constraint.get("is_holder"):
        if type(tmp_constraint.get("is_holder")) is not list:
            holder_list.append(tmp_constraint.get("is_holder"))
        else:
            holder_list = tmp_constraint.get("is_holder")
        for tmp_holder in holder_list:
            holder_list.append(Holder(_field_id=tmp_holder.get("field_id"), directive=tmp_holder.get("directive")))

    if tmp_constraint.get("fields"):
        tmp_fields_list = tmp_constraint.get("fields")
        for tmp_field in tmp_fields_list:
            tmp_path = tmp_field.get("path")
            tmp_purpose = tmp_field.get("purpose")
            tmp_predicate = tmp_field.get("predicate")
            given_filter = None
            if tmp_field.get("filter"):
                tmp_filter_dict = tmp_field.get("filter")
                tmp_fitler_type = tmp_filter_dict.get("type")
                tmp_filter_format = tmp_filter_dict.get("format")
                
                tmp_filter_not = False
                if tmp_filter_dict.get("not"):
                    tmp_filter_not = True
                    tmp_filter_dict = tmp_filter_dict.get("not")
                
                tmp_filter_pattern = tmp_filter_dict.get("pattern")
                tmp_filter_minimum = tmp_filter_dict.get("minimum")
                tmp_filter_maximum = tmp_filter_dict.get("maximum")
                tmp_filter_exclmin = tmp_filter_dict.get("exclusiveMinimum")
                tmp_filter_exclmax = tmp_filter_dict.get("exclusiveMaximum")
                tmp_filter_minlength = tmp_filter_dict.get("minLength")
                tmp_filter_maxlength = tmp_filter_dict.get("maxLength")
                tmp_filter_const = tmp_filter_dict.get("const")
                tmp_filter_enum = tmp_filter_dict.get("enum")

                given_filter = Filter(
                    _not=tmp_filter_not,
                    _type=tmp_fitler_type,
                    _format=tmp_filter_format,
                    pattern=tmp_filter_pattern,
                    minimum=tmp_filter_minimum,
                    maximum=tmp_filter_maximum,
                    min_length=tmp_filter_minlength,
                    max_length=tmp_filter_maxlength,
                    exclusive_min=tmp_filter_exclmin,
                    exclusive_max=tmp_filter_exclmax,
                    const=tmp_filter_const,
                    _enum=tmp_filter_enum,
                )

            field_list.append(Field(
                path=tmp_path,
                purpose=tmp_purpose,
                predicate=tmp_predicate,
                _filter=given_filter,
            ))

    if len(holder_list)==0:
        holder_list=None

    if len(field_list)==0:
        field_list=None

    constraint = Constraints(
        subject_issuer=tmp_subject_is_issuer,
        limit_disclosure=tmp_limit_disclosure,
        holder=holder_list,
        _fields=field_list,
    )
    return constraint

def to_input_desc_schema(descriptor_dict: dict) -> Sequence[SchemaInputDescriptor]:
    extracted_schema_list = []
    schema_list = []
    if type(descriptor_dict.get("schema")) is not list:
        extracted_schema_list.append(descriptor_dict.get("schema"))
    else:
        extracted_schema_list = descriptor_dict.get("schema")
    for tmp_schema_dict in extracted_schema_list:
        tmp_uri = tmp_schema_dict.get("uri")
        tmp_required = tmp_schema_dict.get("required") or False    
        schema_list.append(SchemaInputDescriptor(uri=tmp_uri, required=tmp_required))
    return schema_list

def to_pd(pres_exch_attach: dict) -> PresentationDefinition:
    submission_req_list = []
    input_descriptor_list = []
    format_list = []

    if pres_exch_attach.get("submission_requirements"):
        extracted_sub_req_list = []
        if type(pres_exch_attach.get("submission_requirements")) is not list:
            extracted_sub_req_list.append(pres_exch_attach.get("submission_requirements"))
        else:
            extracted_sub_req_list = pres_exch_attach.get("submission_requirements")
        for tmp_sub_req in extracted_sub_req_list:
            nested_req_list = []
            if tmp_sub_req.get("from_nested"):
                for req_dict in tmp_sub_req.get("from_nested"):
                    nested_req_list.append(to_sr(req_dict))
                submission_req_list.append(to_sr(tmp_sub_req, nested_req_list))
            else:
                submission_req_list.append(to_sr(tmp_sub_req))

    if pres_exch_attach.get("input_descriptors"):
        extracted_inp_desc_list = []
        if type(pres_exch_attach.get("input_descriptors")) is not list:
            extracted_inp_desc_list.append(pres_exch_attach.get("input_descriptors"))
        else:
            extracted_inp_desc_list = pres_exch_attach.get("input_descriptors")
        for tmp_input_desc in extracted_inp_desc_list:
            input_descriptor_list.append(to_input_desc(tmp_input_desc))

    if pres_exch_attach.get("format"):
        format_dict = pres_exch_attach.get("format")
        for tmp_format in format_dict.keys():
            new_claim_fmt = ClaimFormat(format_type=tmp_format, format_data=format_dict.get(tmp_format))
            format_list.append(new_claim_fmt)

    if len(submission_req_list) == 0:
        submission_req_list = None
    if len(input_descriptor_list) == 0:
        input_descriptor_list = None
    if len(format_list) == 0:
        format_list = None

    return PresentationDefinition(
        _id=pres_exch_attach.get("id"),
        name=pres_exch_attach.get("name"),
        purpose=pres_exch_attach.get("purpose"),
        fmt=format_list,
        submission_requirements=submission_req_list,
        input_descriptors=input_descriptor_list,
    )

if __name__ == "__main__":
    test()

