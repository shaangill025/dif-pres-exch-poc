"""Schemas for dif presentation exchange attachment."""

from marshmallow import fields, validate, validates_schema, EXCLUDE, pre_load, Schema, ValidationError, post_dump, post_load
from valid import (
    BASE64,
    WHOLE_NUM,
    UUID4,
    INDY_ISO8601_DATETIME,
)
from typing import Sequence, Union

class ClaimFormat:
    """Defines Claim field."""

    class Meta:
        """ClaimFormat metadata."""

        schema_class = "ClaimFormatSchema"

    def __init__(
        self,
        *,
        jwt_format_data: Sequence[str] = None,
        jwt_vc_format_data: Sequence[str] = None,
        jwt_vp_format_data: Sequence[str] = None,
        ldp_format_data: Sequence[str] = None,
        ldp_vc_format_data: Sequence[str] = None,
        ldp_vp_format_data: Sequence[str] = None,
    ):
        """Initialize format."""
        self.jwt_format_data = jwt_format_data
        self.jwt_vc_format_data = jwt_vc_format_data
        self.jwt_vp_format_data = jwt_vp_format_data
        self.ldp_format_data = ldp_format_data
        self.ldp_vc_format_data = ldp_vc_format_data
        self.ldp_vp_format_data = ldp_vp_format_data

class ClaimFormatSchema(Schema):
    """Single ClaimFormat Schema."""

    class Meta:

        model_class = ClaimFormat
        unknown = EXCLUDE

    jwt_format_data = fields.List(
        fields.Str(
            required=False
        ),
        required=False,
        data_key="jwt",
    )
    jwt_vc_format_data = fields.List(
        fields.Str(
            required=False
        ),
        required=False,
        data_key="jwt_vc",
    )
    jwt_vp_format_data = fields.List(
        fields.Str(
            required=False
        ),
        required=False,
        data_key="jwt_vp",
    )
    ldp_format_data = fields.List(
        fields.Str(
            required=False
        ),
        required=False,
        data_key="ldp",
    )
    ldp_vc_format_data = fields.List(
        fields.Str(
            required=False
        ),
        required=False,
        data_key="ldp_vc",
    )
    ldp_vp_format_data = fields.List(
        fields.Str(
            required=False
        ),
        required=False,
        data_key="ldp_vp",
    )

    @pre_load
    def extract_info(self, data, **kwargs):
        if "jwt" in data:
            data["jwt"] = data["jwt"].pop('alg')
        if "jwt_vc" in data:
            data["jwt_vc"] = data["jwt_vc"].pop('alg')
        if "jwt_vp" in data:
            data["jwt_vp"] = data["jwt_vp"].pop('alg')
        if "ldp" in data:
            data["ldp"] = data["ldp"].pop('proof_type')
        if "ldp_vc" in data:
            data["ldp_vc"] = data["ldp_vc"].pop('proof_type')
        if "ldp_vp" in data:
            data["ldp_vp"] = data["ldp_vp"].pop('proof_type')
        return data

    @post_dump
    def reformat_data(self, data, **kwargs):
        reformat = {}
        if "jwt" in data:
            tmp_dict = {}
            tmp_dict["alg"] = data.get("jwt")
            reformat["jwt"] = tmp_dict
        if "jwt_vc" in data:
            tmp_dict = {}
            tmp_dict["alg"] = data.get("jwt_vc")
            reformat["jwt_vc"] = tmp_dict
        if "jwt_vp" in data:
            tmp_dict = {}
            tmp_dict["alg"] = data.get("jwt_vp")
            reformat["jwt_vp"] = tmp_dict
        if "ldp" in data:
            tmp_dict = {}
            tmp_dict["proof_type"] = data.get("ldp")
            reformat["ldp"] = tmp_dict
        if "ldp_vc" in data:
            tmp_dict = {}
            tmp_dict["proof_type"] = data.get("ldp_vc")
            reformat["ldp_vc"] = tmp_dict
        if "ldp_vp" in data:
            tmp_dict = {}
            tmp_dict["proof_type"] = data.get("ldp_vp")
            reformat["ldp_vp"] = tmp_dict
        return reformat
    
    @post_load
    def make_object(self, data, **kwargs):
        return ClaimFormat(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }


class SubmissionRequirements:
    """SubmissionRequirement describes input that must be submitted via a presentation submission."""

    class Meta:
        """SubmissionRequirements metadata."""

        schema_class = "SubmissionRequirementsSchema"

    def __init__(
        self,
        *,
        _name: str = None,
        purpose: str = None,
        rule: str = None,
        count: int = None,
        minimum: int = None,
        maximum: int = None,
        _from: str = None,
        # Self_reference
        _from_nested: Sequence = None,
    ):
        """Initialize SubmissionRequirement."""
        self._name = _name
        self.purpose = purpose
        self.rule = rule
        self.count = count
        self.minimum = minimum
        self.maximum = maximum
        self._from = _from
        self._from_nested = _from_nested


class SubmissionRequirementsSchema(Schema):
    """Single Presentation Definition Schema."""

    class Meta:

        model_class = SubmissionRequirements
        unknown = EXCLUDE

    _name = fields.Str(
        description="Name", required=False, data_key="name"
    )
    purpose = fields.Str(
        description="Purpose", required=False, data_key="purpose"
    )
    rule = fields.Str(
        description="Selection",
        required=False,
        validate=validate.OneOf(["all", "pick"]),
        data_key="rule",
    )
    count = fields.Int(
        description="Count Value",
        example=1234,
        required=False,
        strict=True,
        data_key="count",
    )
    minimum = fields.Int(
        description="Min Value",
        example=1234,
        required=False,
        strict=True,
        data_key="min"
    )
    maximum = fields.Int(
        description="Max Value",
        example=1234,
        required=False,
        strict=True,
        data_key="max"
    )
    _from = fields.Str(
        description="From", required=False, data_key="from"
    )
    # Self References
    _from_nested = fields.List(
        fields.Nested(lambda: SubmissionRequirementsSchema(exclude=("_from_nested",))),
        required=False,
        data_key="from_nested",
    )

    @post_load
    def make_object(self, data, **kwargs):
        return SubmissionRequirements(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class SchemaInputDescriptor:
    """SchemaField."""

    class Meta:
        """SchemaField metadata."""

        schema_class = "SchemaFieldSchema"

    def __init__(
        self,
        *,
        uri: str = None,
        required: bool = None,
    ):
        """Initialize InputDescriptors."""
        self.uri = uri
        self.required = required


class SchemaInputDescriptorSchema(Schema):
    """Single SchemaField Schema."""

    class Meta:

        model_class = SchemaInputDescriptor
        unknown = EXCLUDE

    uri = fields.Str(
        description="URI",
        required=False,
        data_key="uri",
    )
    required = fields.Bool(
        description="Required",
        required=False,
        data_key="required"
    )

    @post_load
    def make_object(self, data, **kwargs):
        return SchemaInputDescriptor(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class Holder:
    """Single Holder object for Constraints."""

    class Meta:
        """Holder metadata."""

        schema_class = "HolderSchema"

    def __init__(
        self,
        *,
        _field_id: Sequence[str] = None,
        directive: str = None,
    ):
        """Initialize Holder."""
        self._field_id = _field_id
        self.directive = directive


class HolderSchema(Schema):
    """Single Holder Schema."""

    class Meta:

        model_class = Holder
        unknown = EXCLUDE

    _field_id = fields.List(
        fields.Str(
            description="FieldID",
            required=False,
            **UUID4,
        ),
        required=False,
        data_key="field_id",
    )
    directive = fields.Str(
        description="Preference",
        required=False,
        validate=validate.OneOf(["required", "preferred"]),
        data_key="directive",
    )

    @post_load
    def make_object(self, data, **kwargs):
        return Holder(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class Filter:
    """Single Filter."""

    class Meta:
        """Filter metadata."""

        schema_class = "FilterSchema"

    def __init__(
        self,
        *,
        _not: bool = False,
        _type: str = None,
        _format: str = None,
        pattern: str = None,
        minimum: str = None,
        maximum: str = None,
        min_length: int = None,
        max_length: int = None,
        exclusive_min: str = None,
        exclusive_max: str = None,
        const: str = None,
        _enum: Sequence[str] = None,
    ):
        """Initialize Filter."""
        self._type = _type
        self._format = _format
        self.pattern = pattern
        self.minimum = minimum
        self.maximum = maximum
        self.min_length = min_length
        self.max_length = max_length
        self.exclusive_min = exclusive_min
        self.exclusive_max = exclusive_max
        self.const = const
        self._enum = _enum
        self._not = _not


class FilterSchema(Schema):
    """Single Presentation Definition Schema."""

    class Meta:

        model_class = Filter
        unknown = EXCLUDE

    _type = fields.Str(
        description="Type",
        required=False,
        data_key="type"
    )
    _format = fields.Str(
        description="Format",
        required=False,
        data_key="format",
    )
    pattern = fields.Str(
        description="Pattern",
        required=False,
        data_key="pattern",
    )
    minimum = fields.Str(
        description="Minimum, can be str or int",
        required=False,
        data_key="minimum",
    )
    maximum = fields.Str(
        description="Maximum, can be str or int",
        required=False,
        data_key="maximum",
    )
    min_length = fields.Int(
        description="Min Length",
        example=1234,
        strict=True,
        required=False,
        data_key="minLength",
    )
    max_length = fields.Int(
        description="Max Length",
        example=1234,
        strict=True,
        required=False,
        data_key="maxLength"
    )
    exclusive_min = fields.Str(
        description="ExclusiveMinimum, can be str or int",
        required=False,
        data_key="exclusiveMinimum",
    )
    exclusive_max = fields.Str(
        description="ExclusiveMaximum, can be str or int",
        required=False,
        data_key="exclusiveMaximum",
    )
    const = fields.Str(
        description="Const, can be str or int",
        required=False,
        data_key="const",
    )
    _enum = fields.List(
        fields.Str(
            description="Enum, can be str or int",
            required=False
        ),
        required=False,
        data_key="enum",
    )
    _not = fields.Boolean(
        description="Not",
        required=False,
        example=False,
        data_key="not",
    )
    
    @post_load
    def make_object(self, data, **kwargs):
        return Filter(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class Field:
    """Single Field object for the Constraint."""

    class Meta:
        """Field metadata."""

        schema_class = "FieldSchema"

    def __init__(
        self,
        *,
        path: Sequence[str] = None,
        purpose: str = None,
        predicate: str = None,
        _filter: Filter = None,
    ):
        """Initialize Field."""
        self.path = path
        self.purpose = purpose
        self.predicate = predicate
        self._filter = _filter


class FieldSchema(Schema):
    """Single Field Schema."""

    class Meta:

        model_class = Field
        unknown = EXCLUDE

    path = fields.List(
        fields.Str(
            description="Path",
            required=False
        ),
        required=False,
        data_key="path",
    )
    purpose = fields.Str(
        description="Purpose",
        required=False,
        data_key="purpose",
    )
    predicate = fields.Str(
        description="Preference",
        required=False,
        validate=validate.OneOf(["required", "preferred"]),
        data_key="predicate",
    )
    _filter = fields.Nested(FilterSchema, data_key="filter")

    @post_load
    def make_object(self, data, **kwargs):
        return Field(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class Constraints:
    """Single Constraints which describes InputDescriptor's Contraint field."""

    class Meta:
        """Constraints metadata."""

        schema_class = "ConstraintsSchema"

    def __init__(
        self,
        *,
        subject_issuer: str = None,
        limit_disclosure: bool = None,
        holder: Sequence[Holder] = None,
        _fields: Sequence[Field] = None,
        status_active: str = None,
        status_suspended: str = None,
        status_revoked: str = None,
    ):
        """Initialize Constraints for Input Descriptor."""
        self.subject_issuer = subject_issuer
        self.limit_disclosure = limit_disclosure
        self.holder = holder
        self._fields = _fields
        self.status_active = status_active
        self.status_suspended = status_suspended
        self.status_revoked = status_revoked


class ConstraintsSchema(Schema):
    """Single Constraints Schema."""

    class Meta:

        model_class = Constraints
        unknown = EXCLUDE

    subject_issuer = fields.Str(
        description="SubjectIsIssuer",
        required=False,
        validate=validate.OneOf(["required", "preferred"]),
        data_key="subject_is_issuer"
    )
    limit_disclosure = fields.Bool(
        description="LimitDisclosure",
        required=False,
        data_key="limit_disclosure"
    )
    holder = fields.List(
        fields.Nested(HolderSchema),
        required=False,
        data_key="is_holder",
    )
    _fields = fields.List(
        fields.Nested(FieldSchema),
        required=False,
        data_key="fields",
    )
    status_active = fields.Str(
        required=False,
        validate=validate.OneOf(["required", "allowed", "disallowed"]),
    )
    status_suspended = fields.Str(
        required=False,
        validate=validate.OneOf(["required", "allowed", "disallowed"]),
    )
    status_revoked = fields.Str(
        required=False,
        validate=validate.OneOf(["required", "allowed", "disallowed"]),
    )

    @pre_load
    def extract_info(self, data, **kwargs):
        if "statuses" in data:
            if "active" in data.get("statuses"):
                if "directive" in data.get("statuses").get("active"):
                    data["status_active"] = data["statuses"]["active"]["directive"]
            if "suspended" in data.get("statuses"):
                if "directive" in data.get("statuses").get("suspended"):
                    data["status_suspended"] = data["statuses"]["suspended"]["directive"]
            if "revoked" in data.get("statuses"):
                if "directive" in data.get("statuses").get("revoked"):
                    data["status_revoked"] = data["statuses"]["revoked"]["directive"]
        return data

    @post_dump
    def reformat_data(self, data, **kwargs):
        if "status_active" in data:
            tmp_dict = {}
            tmp_dict["directive"] = data.get("status_active")
            if "statuses" in data:
                tmp_dict2 = data.get("statuses")
            else:
                tmp_dict2 = {}
            tmp_dict2["active"] = tmp_dict
            data['statuses'] = tmp_dict2
            del data["status_active"]
        if "status_suspended" in data:
            tmp_dict = {}
            tmp_dict["directive"] = data.get("status_suspended")
            if "statuses" in data:
                tmp_dict2 = data.get("statuses")
            else:
                tmp_dict2 = {}
            tmp_dict2["suspended"] = tmp_dict
            data['statuses'] = tmp_dict2
            del data["status_suspended"]
        if "status_revoked" in data:
            tmp_dict = {}
            tmp_dict["directive"] = data.get("status_revoked")
            if "statuses" in data:
                tmp_dict2 = data.get("statuses")
            else:
                tmp_dict2 = {}
            tmp_dict2["revoked"] = tmp_dict
            data['statuses'] = tmp_dict2
            del data["status_revoked"]
        return data

    @post_load
    def make_object(self, data, **kwargs):
        return Constraints(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class InputDescriptors:
    """Input Descriptors."""

    class Meta:
        """InputDescriptors metadata."""

        schema_class = "InputDescriptorsSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        group: Sequence[str] = None,
        name: str = None,
        purpose: str = None,
        metadata: dict = None,
        constraint: Constraints = None,
        _schema: Sequence[SchemaInputDescriptor] = None,
    ):
        """Initialize InputDescriptors."""
        self._id = _id
        self.group = group
        self.name = name
        self.purpose = purpose
        self.metadata = metadata
        self.constraint = constraint
        self._schema = _schema


class InputDescriptorsSchema(Schema):
    """Single InputDescriptors Schema."""

    class Meta:

        model_class = InputDescriptors
        unknown = EXCLUDE

    _id = fields.Str(
        description="ID",
        required=False,
        data_key="id"
    )
    group = fields.List(
        fields.Str(
            description="Group",
            required=False,
        ),
        required=False,
        data_key="group"
    )
    name = fields.Str(
        description="Name", required=False, data_key="name"
    )
    purpose = fields.Str(
        description="Purpose", required=False, data_key="purpose"
    )
    metadata = fields.Dict(
        description="Metadata dictionary", required=False, data_key="metadata"
    )
    constraint = fields.Nested(ConstraintsSchema, required=False, data_key="constraints")
    _schema = fields.List(
        fields.Nested(SchemaInputDescriptorSchema),
        required=False,
        data_key="schema"
    )

    @post_load
    def make_object(self, data, **kwargs):
        return InputDescriptors(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class Requirement:
    """Single Requirement generated from toRequirement function."""

    class Meta:
        """Requirement metadata."""

        schema_class = "RequirementSchema"

    def __init__(
        self,
        *,
        count: int = None,
        maximum: int = None,
        minimum: int = None,
        _input_descriptors: Sequence[InputDescriptors] = None,
        _nested_req: Sequence = None,
    ):
        """Initialize Requirement."""
        self.count = count
        self.maximum = maximum
        self.minimum = minimum
        self._input_descriptors = _input_descriptors
        self._nested_req = _nested_req


class RequirementSchema(Schema):
    """Single Requirement Schema."""

    class Meta:

        model_class = Requirement
        unknown = EXCLUDE

    count = fields.Int(
        description="Count Value",
        example=1234,
        strict=True,
        required=False,
    )
    maximum = fields.Int(
        description="Max Value",
        example=1234,
        strict=True,
        required=False,
    )
    minimum = fields.Int(
        description="Min Value",
        example=1234,
        strict=True,
        required=False,
    )
    _input_descriptors = fields.List(
        fields.Nested(InputDescriptorsSchema),
        required=False,
    )
    # Self References
    _nested_req = fields.List(
        fields.Nested(lambda: RequirementSchema(exclude=("_nested_req",))),
        required=False,
    )

    @post_load
    def make_object(self, data, **kwargs):
        return Requirement(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }


class PresentationDefinition:
    """Single PresentationDefinition (https://identity.foundation/presentation-exchange/)"""

    class Meta:
        """PresentationDefinition metadata."""

        schema_class = "PresentationDefinitionSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        name: str = None,
        purpose: str = None,
        fmt: ClaimFormat = None,
        submission_requirements: Sequence[SubmissionRequirements] = None,
        input_descriptors: Sequence[InputDescriptors] = None,
        **kwargs,
    ):
        """Initialize flattened single-JWS to include in attach decorator data."""
        super().__init__(**kwargs)
        self._id = _id
        self.name = name
        self.purpose = purpose
        self.fmt = fmt
        self.submission_requirements = submission_requirements
        self.input_descriptors = input_descriptors


class PresentationDefinitionSchema(Schema):
    """Single Presentation Definition Schema."""

    class Meta:

        model_class = PresentationDefinition
        unknown = EXCLUDE

    _id = fields.Str(
        required=False,
        description="Unique Resource Identifier",
        **UUID4,
        data_key="id",
    )
    name = fields.Str(
        description="Human-friendly name that describes what the presentation definition pertains to",
        required=False,
        data_key="name",
    )
    purpose = fields.Str(
        description="Describes the purpose for which the Presentation Definition's inputs are being requested",
        required=False,
        data_key="purpose",
    )
    fmt = fields.Nested(ClaimFormatSchema,
        required=False,
        data_key="format",
    )
    submission_requirements = fields.List(
        fields.Nested(SubmissionRequirementsSchema),
        required=False,
        data_key="submission_requirements",
    )
    input_descriptors = fields.List(
        fields.Nested(InputDescriptorsSchema),
        required=False,
        data_key="input_descriptors",
    )


    @post_load
    def make_object(self, data, **kwargs):
        return PresentationDefinition(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }


class TypedID:
    """Single TypedID object for the VerifiableCredential."""

    class Meta:
        """TypedID metadata."""

        schema_class = "TypedIDSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        _type: str = None,
        custom_field: dict = None,
    ):
        """Initialize TypedID."""
        self._id = _id
        self._type = _type
        self.custom_field = custom_field


class TypedIDSchema(Schema):
    """Single TypedID Schema."""

    class Meta:

        model_class = TypedID
        unknown = EXCLUDE
    
    _id = fields.Str(
        description="ID",
        required=False,
        data_key="id",
    )
    _type = fields.Str(
        description="Type",
        required=False,
        data_key="type",
    )
    custom_field = fields.Dict(
        description="CustomField",
        required=False
    )

    @post_load
    def make_object(self, data, **kwargs):
        return TypedID(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }

class VerifiableCredential:
    """Single VerifiableCredential object."""

    class Meta:
        """VerifiableCredential metadata."""

        schema_class = "VerifiableCredentialSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        context: Sequence[str] = None,
        custom_context: Sequence[dict] = None,
        _types: Sequence[str] = None,
        subject: dict = None,
        issued: str = None,
        expired: str = None,
        proofs: Sequence[dict] = None,
        custom_field: dict = None,
        evidence: Sequence[dict] = None,
        status: TypedID = None,
        schemas: Sequence[TypedID] = None,
        terms_of_use: Sequence[TypedID] = None,
        refresh_service: Sequence[TypedID] = None,
        issuer: str = None,
        provided_cred_json: dict = None
    ):
        """Initialize VerifiableCredential."""
        self._id = _id
        self.context = context
        self.custom_context = custom_context
        self._types = _types
        self.subject = subject
        self.issued = issued
        self.expired = expired
        self.proofs = proofs
        self.custom_field = custom_field
        self.evidence = evidence
        self.status = status
        self.schemas = schemas
        self.terms_of_use = terms_of_use
        self.refresh_service = refresh_service
        self.issuer = issuer
        self.provided_cred_json = provided_cred_json


class VerifiableCredentialSchema(Schema):
    """Single VerifiableCredential Schema."""

    class Meta:

        model_class = VerifiableCredential
        unknown = EXCLUDE

    _id = fields.Str(
        description="ID",
        required=False,
        data_key="id",
    )
    context = fields.List(
        fields.Str(
            description="Context",
            required=False
        ),
        data_key="@context",
    )
    custom_context = fields.List(
        fields.Dict(
            description="CustomContext",
            required=False
        ),
    )
    _types = fields.List(
        fields.Str(
            description="Type",
            required=False
        ),
        data_key="type",
    )
    subject = fields.Dict(
        description="Subject",
        required=False,
        data_key="credentialSubject",
    )
    issued = fields.Str(
        required=False,
        description="Issued",
        **INDY_ISO8601_DATETIME,
        data_key="issuanceDate",
    )
    expired = fields.Str(
        required=False,
        description="Expired",
        **INDY_ISO8601_DATETIME,
        data_key="expirationDate",
    )
    proofs = fields.List(
        fields.Dict(
            description="Proof",
            required=False
        ),
        data_key="proof",
    )
    custom_field = fields.Dict(
        description="CustomField",
        required=False
    )
    evidence = fields.List(
        fields.Dict(
            description="Evidence",
            required=False
        ),
        data_key="evidence",
    )
    status = fields.Nested(TypedIDSchema, data_key="credentialStatus")
    schemas = fields.List(
        fields.Nested(TypedIDSchema),
        data_key="credentialSchema",
    )
    terms_of_use = fields.List(
        fields.Nested(TypedIDSchema),
        data_key="termsOfUse",
    )
    refresh_service = fields.List(
        fields.Nested(TypedIDSchema),
        data_key="refreshService",
    )
    issuer = fields.Str(
        description="Issuer",
        required=False,
        data_key="issuer",
    )
    provided_cred_json = fields.Dict(required=False)

    @pre_load
    def extract_info(self, data, **kwargs):
        if "credentialSchema" in data:
            if type(data.get("credentialSchema")) is not list:
                tmp_list = []
                tmp_list.append(data.get("credentialSchema"))
                data["credentialSchema"] = tmp_list
        if "proof" in data:
            if type(data.get("proof")) is not list:
                tmp_list = []
                tmp_list.append(data.get("proof"))
                data["proof"] = tmp_list
        data["provided_cred_json"] = data
        return data

    @post_dump
    def reformat_data(self, data, **kwargs):
        if "provided_cred_json" in data:
            del data["provided_cred_json"]
        return data

    @post_load
    def make_object(self, data, **kwargs):
        return VerifiableCredential(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }


class InputDescriptorMapping:
    """Single InputDescriptorMapping object."""

    class Meta:
        """InputDescriptorMapping metadata."""

        schema_class = "InputDescriptorMappingSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        _format: str = None,
        path: str = None,
    ):
        """Initialize InputDescriptorMapping."""
        self._id = _id
        self._format = _format
        self.path = path


class InputDescriptorMappingSchema(Schema):
    """Single InputDescriptorMapping Schema."""

    class Meta:

        model_class = InputDescriptorMapping
        unknown = EXCLUDE
    
    _id = fields.Str(
        description="ID",
        required=False,
        data_key="id",
    )
    _format = fields.Str(
        description="Format",
        required=False,
        default="ldp_vp",
        data_key="format",
    )
    path = fields.Str(
        description="Path",
        required=False,
        data_key="path",
    )

    @post_load
    def make_object(self, data, **kwargs):
        return InputDescriptorMapping(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }


class PresentationSubmission:
    """Single PresentationSubmission object."""

    class Meta:
        """PresentationSubmission metadata."""

        schema_class = "PresentationSubmissionSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        definition_id: str = None,
        descriptor_map: Sequence[InputDescriptorMapping] = None,
    ):
        """Initialize InputDescriptorMapping."""
        self._id = _id
        self.definition_id = definition_id
        self.descriptor_map = descriptor_map


class PresentationSubmissionSchema(Schema):
    """Single PresentationSubmission Schema."""

    class Meta:

        model_class = PresentationSubmission
        unknown = EXCLUDE
    
    _id = fields.Str(
        description="ID",
        required=False,
        **UUID4,
        data_key="id",
    )
    definition_id = fields.Str(
        description="DefinitionID",
        required=False,
        **UUID4,
        data_key="definition_id",
    )
    descriptor_map = fields.List(
        fields.Nested(InputDescriptorMapping),
        required=False,
        data_key="descriptor_map",
    )

    @post_load
    def make_object(self, data, **kwargs):
        return PresentationSubmission(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }


class VerifiablePresentation:
    """Single VerifiablePresentation object."""

    class Meta:
        """VerifiablePresentation metadata."""

        schema_class = "VerifiablePresentationSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        context: Sequence[str] = None,
        custom_context: Sequence[dict] = None,
        _types: Sequence[str] = None,
        credentials: Sequence[dict] = None,
        holder: str = None,
        proofs: Sequence[dict] = None,
        custom_field: dict = None,
        presentation_submission: PresentationSubmission = None,
    ):
        """Initialize VerifiablePresentation."""
        self._id = _id
        self.context = context
        self.custom_context = custom_context
        self._types = _types
        self.credentials = credentials
        self.holder = holder
        self.proofs = proofs
        self.custom_field = custom_field
        self.presentation_submission = presentation_submission


class VerifiablePresentationSchema(Schema):
    """Single Field Schema."""

    class Meta:

        model_class = VerifiablePresentation
        unknown = EXCLUDE
    
    _id = fields.Str(
        description="ID",
        required=False,
        **UUID4,
        data_key="id",
    )
    context = fields.List(
        fields.Str(
            description="Context",
            required=False
        ),
        data_key="@context",
    )
    custom_context = fields.List(
        fields.Dict(
            description="CustomContext",
            required=False
        ),
    )
    _types = fields.List(
        fields.Str(
            description="Types",
            required=False
        ),
        data_key="type",
    )
    credentials = fields.List(
        fields.Dict(
            description="Credentials",
            required=False
        ),
        data_key="verifiableCredential",
    )
    holder = fields.Str(
        description="Holder",
        required=False,
        data_key="holder",
    )
    proofs = fields.List(
        fields.Dict(
            description="Proof",
            required=False
        ),
        data_key="proof",
    )
    custom_field = fields.Dict(
        description="CustomField",
        required=False
    )
    presentation_submission = fields.Nested(PresentationSubmissionSchema, data_key="presentation_submission")

    @pre_load
    def extract_info(self, data, **kwargs):
        if "proof" in data:
            if type(data.get("proof")) is not list:
                tmp_list = []
                tmp_list.append(data.get("proof"))
                data["proof"] = tmp_list
        return data

    @post_dump
    def reformat_data(self, data, **kwargs):
        if "id" in data:
            del data["id"]
        return data

    @post_load
    def make_object(self, data, **kwargs):
        return VerifiablePresentation(**data)

    @post_dump
    def remove_null_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items()
            if value is not None
        }


