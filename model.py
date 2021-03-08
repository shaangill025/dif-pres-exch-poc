"""Schemas for dif presentation exchange attachment."""

from marshmallow import fields, validate, validates_schema, EXCLUDE, pre_load, Schema
from valid import (
    BASE64,
    WHOLE_NUM,
    UUID4,
    INDY_ISO8601_DATETIME,
)
from typing import Sequence, Union


class ClaimFormat(object):
    """Defines Claim field."""

    class Meta:
        """ClaimFormat metadata."""

        schema_class = "ClaimFormatSchema"

    def __init__(
        self,
        *,
        format_type: str = None,
        format_data: Sequence[str] = None,
    ):
        """Initialize format."""
        self.format_type = format_type
        self.format_data = format_data


class ClaimFormatSchema(Schema):
    """Single ClaimFormat Schema."""

    class Meta:

        model_class = ClaimFormat
        unknown = EXCLUDE

    format_type = fields.Str(
        description="Defines format type",
        required=False,
        validate=validate.OneOf(["jwt", "jwt_vc", "jwt_vp", "ldp", "ldp_vc", "ldp_vp"])
    )
    format_data = fields.List(
        fields.Str(
            description="Contains either JwtType alg or LdpType proof_type",
            required=False,
        ),
        required=False,
    )


class SubmissionRequirements(object):
    """SubmissionRequirement describes input that must be submitted via a presentation submission."""

    class Meta:
        """SubmissionRequirements metadata."""

        schema_class = "SubmissionRequirementsSchema"

    def __init__(
        self,
        *,
        name: str = None,
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
        self.name = name
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
        description="Name", required=False
    )
    purpose = fields.Str(
        description="Purpose", required=False
    )
    rule = fields.Str(
        description="Selection",
        required=False,
        validate=validate.OneOf(["all", "pick"])
    )
    count = fields.Int(
        description="Count Value",
        example=1234,
        required=False,
        strict=True,
    )
    minimum = fields.Int(
        description="Min Value",
        example=1234,
        required=False,
        strict=True,
    )
    maximum = fields.Int(
        description="Max Value",
        example=1234,
        required=False,
        strict=True,
    )
    _from = fields.Str(
        description="From", required=False
    )
    # Self References
    _from_nested = fields.List(
        fields.Nested("SubmissionRequirementsSchema"),
        required=False,
    )


class SchemaInputDescriptor(object):
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
    )
    required = fields.Bool(
        description="Required",
        required=False,
    )


class Holder(object):
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
    )
    directive = fields.Str(
        description="Preference",
        required=False,
        validate=validate.OneOf(["required", "preferred"])
    )



class Filter(object):
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
        required=False
    )
    _format = fields.Str(
        description="Format",
        required=False
    )
    pattern = fields.Str(
        description="Pattern",
        required=False
    )
    minimum = fields.Str(
        description="Minimum, can be str or int",
        required=False
    )
    maximum = fields.Str(
        description="Maximum, can be str or int",
        required=False
    )
    min_length = fields.Int(
        description="Min Length",
        example=1234,
        strict=True,
        required=False,
    )
    max_length = fields.Int(
        description="Max Length",
        example=1234,
        strict=True,
        required=False,
    )
    exclusive_min = fields.Str(
        description="ExclusiveMinimum, can be str or int",
        required=False
    )
    exclusive_max = fields.Str(
        description="ExclusiveMaximum, can be str or int",
        required=False
    )
    const = fields.Str(
        description="Const, can be str or int",
        required=False
    )
    _enum = fields.List(
        fields.Str(
            description="Enum, can be str or int",
            required=False
        ),
        required=False,
    )
    _not = fields.Boolean(
        description="Not",
        required=False,
        example=False,
    )
    

class Field(object):
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
    )
    purpose = fields.Str(
        description="Purpose",
        required=False
    )
    predicate = fields.Str(
        description="Preference",
        required=False,
        validate=validate.OneOf(["required", "preferred"])
    )
    _filter = fields.Nested(FilterSchema, required=False)



class Constraints(object):
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
    ):
        """Initialize Constraints for Input Descriptor."""
        self.subject_issuer = subject_issuer
        self.limit_disclosure = limit_disclosure
        self.holder = holder
        self._fields = _fields


class ConstraintsSchema(Schema):
    """Single Constraints Schema."""

    class Meta:

        model_class = Constraints
        unknown = EXCLUDE

    subject_issuer = fields.Str(
        description="SubjectIsIssuer",
        required=False,
        validate=validate.OneOf(["required", "preferred"])
    )
    limit_disclosure = fields.Bool(
        description="LimitDisclosure",
        required=False,
    )
    holder = fields.List(
        fields.Nested(HolderSchema),
        required=False,
    )
    _fields = fields.List(
        fields.Nested(FieldSchema),
        required=False,
    )



class InputDescriptors(object):
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
    )
    group = fields.List(
        fields.Str(
            description="Group",
            required=False,
        ),
        required=False,
    )
    name = fields.Str(
        description="Name", required=False
    )
    purpose = fields.Str(
        description="Purpose", required=False
    )
    metadata = fields.Dict(
        description="Metadata dictionary", required=False
    )
    constraint = fields.Nested(ConstraintsSchema, required=False)
    _schema = fields.List(
        fields.Nested(SchemaInputDescriptorSchema),
        required=False,
    )


class Requirement(object):
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
        fields.Nested("RequirementSchema"),
        required=False,
    )


class PresentationDefinition(object):
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
        locale: str = None,
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
        self.locale = locale
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
    )
    name = fields.Str(
        description="Human-friendly name that describes what the presentation definition pertains to",
        required=False,
    )
    purpose = fields.Str(
        description="Describes the purpose for which the Presentation Definition's inputs are being requested",
        required=False,
    )
    locale = fields.Str(
        description="Locale",
        required=False,
    )
    fmt = fields.List(
        fields.Nested(ClaimFormat),
        required=False,
    )
    submission_requirements = fields.List(
        fields.Nested(SubmissionRequirementsSchema),
        required=False,
    )
    input_descriptors = fields.List(
        fields.Nested(InputDescriptorsSchema),
        required=False,
    )


class TypedID(object):
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
        **UUID4,
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


class Issuer(object):
    """Single Issuer for the VerifiableCredential."""

    class Meta:
        """Issuer metadata."""

        schema_class = "IssuerSchema"

    def __init__(
        self,
        *,
        _id: str = None,
        custom_field: dict = None,
    ):
        """Initialize Issuer."""
        self._id = _id
        self.custom_field = custom_field


class IssuerSchema(Schema):
    """Single Issuer Schema."""

    class Meta:

        model_class = Issuer
        unknown = EXCLUDE
    
    _id = fields.Str(
        description="ID",
        required=False,
        data_key="id",
    )
    custom_field = fields.Dict(
        description="CustomField",
        required=False
    )


class VerifiableCredential(object):
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
        issuer: Issuer = None,
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
    status = fields.Nested(TypedIDSchema)
    schemas = fields.List(
        fields.Nested(TypedIDSchema),
        data_key="credentialSchema",
    )
    terms_of_use = fields.List(
        fields.Nested(TypedIDSchema)
    )
    refresh_service = fields.List(
        fields.Nested(TypedIDSchema)
    )
    issuer = fields.Nested(IssuerSchema, data_key="issuer")
    provided_cred_json = fields.Dict(required=False)


class InputDescriptorMapping(object):
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
        **UUID4,
    )
    _format = fields.Str(
        description="Format",
        required=False,
    )
    path = fields.Str(
        description="Path",
        required=False,
    )


class VerifiablePresentation(object):
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


class VerifiablePresentationSchema(Schema):
    """Single Field Schema."""

    class Meta:

        model_class = VerifiablePresentation
        unknown = EXCLUDE
    
    _id = fields.Str(
        description="ID",
        required=False,
        **UUID4,
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
    )
    credentials = fields.List(
        fields.Dict(
            description="Credentials",
            required=False
        ),
    )
    holder = fields.Str(
        description="Holder",
        required=False
    )
    proofs = fields.List(
        fields.Dict(
            description="Proof",
            required=False
        ),
    )
    custom_field = fields.Dict(
        description="CustomField",
        required=False
    )

