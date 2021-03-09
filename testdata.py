import json

vc_dict_list = []

cred_json_1 = """
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "issuer": "https://example.edu/issuers/565049",
  "issuanceDate": "2010-01-01T19:73:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": [{
        "value": "Example University",
        "lang": "en"
      }, {
        "value": "Exemple d'Université",
        "lang": "fr"
      }]
    }
  },
  "credentialSchema": {
    "id": "hub://did:foo:123/Collections/schema.us.gov/passport.json",
    "type": "JsonSchemaValidator2018"
  },
  "proof": {
    "type": "RsaSignature2018",
    "created": "2017-06-18T21:19:10Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://example.edu/issuers/keys/1",
    "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
  }
}
"""

cred_json_2 = """
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "issuer": "https://example.edu/issuers/565049",
  "issuanceDate": "2010-01-01T19:73:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": [{
        "value": "Example University",
        "lang": "en"
      }, {
        "value": "Exemple d'Université",
        "lang": "fr"
      }]
    }
  },
  "credentialSchema": {
    "id": "https://example.org/examples/degree.json",
    "type": "JsonSchemaValidator2018"
  },
  "proof": {
    "type": "RsaSignature2018",
    "created": "2017-06-18T21:19:10Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://example.edu/issuers/keys/1",
    "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
  }
}
"""

cred_json_3 = """
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "issuer": "https://example.edu/issuers/565049",
  "issuanceDate": "2010-01-01T19:73:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": [{
        "value": "Example University",
        "lang": "en"
      }, {
        "value": "Exemple d'Université",
        "lang": "fr"
      }]
    }
  },
  "credentialSchema": {
    "id": "https://eu.com/claims/DriversLicense.json",
    "type": "JsonSchemaValidator2018"
  },
  "proof": {
    "type": "RsaSignature2018",
    "created": "2017-06-18T21:19:10Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://example.edu/issuers/keys/1",
    "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
  }
}
"""
cred_json_4 = """
    {
      "vc": {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "id": "https://eu.com/claims/DriversLicense",
        "type": ["EUDriversLicense"],
        "issuer": "did:example:123",
        "issuanceDate": "2010-01-01T19:73:24Z",
        "credentialSubject": {
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "accounts": [
            {
              "id": "1234567890",
              "route": "DE-9876543210"
            },
            {
              "id": "2457913570",
              "route": "DE-0753197542"
            }
          ]
        }
      }
    }
"""

cred_json_5 = """
    {
      "@context": "https://www.w3.org/2018/credentials/v1",
      "id": "https://business-standards.org/schemas/employment-history.json",
      "type": ["VerifiableCredential", "GenericEmploymentCredential"],
      "issuer": "did:foo:123",
      "issuanceDate": "2010-01-01T19:73:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "dob": "07/13/80"
      },
      "credentialSchema": {
        "id": "https://eu.com/claims/DriversLicense.json",
        "type": "JsonSchemaValidator2018"
      },
      "proof": {
        "type": "EcdsaSecp256k1VerificationKey2019",
        "created": "2017-06-18T21:19:10Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://example.edu/issuers/keys/1",
        "jws": "..."
      }
    }
"""
cred_json_6 = """
    {
      "@context": "https://www.w3.org/2018/credentials/v1",
      "id": "https://eu.com/claims/DriversLicense",
      "type": ["EUDriversLicense"],
      "issuer": "did:foo:123",
      "issuanceDate": "2010-01-01T19:73:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "license": {
          "number": "34DGE352",
          "dob": "07/13/80"
        }
      },
      "credentialSchema": {
        "id": "https://eu.com/claims/DriversLicense.json",
        "type": "JsonSchemaValidator2018"
      },
      "proof": {
        "type": "RsaSignature2018",
        "created": "2017-06-18T21:19:10Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://example.edu/issuers/keys/1",
        "jws": "..."
      }
    }
"""

vc_dict_list.append(json.loads(cred_json_1))
vc_dict_list.append(json.loads(cred_json_2))
vc_dict_list.append(json.loads(cred_json_3))
vc_dict_list.append(json.loads(cred_json_4))
vc_dict_list.append(json.loads(cred_json_5))
vc_dict_list.append(json.loads(cred_json_6))


pd_dict_list = []

pres_exch_1 = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "format": {
    "jwt": {
      "alg": ["EdDSA", "ES256K", "ES384"]
    },
    "jwt_vc": {
      "alg": ["ES256K", "ES384"]
    },
    "jwt_vp": {
      "alg": ["EdDSA", "ES256K"]
    },
    "ldp_vc": {
      "proof_type": [
        "JsonWebSignature2020",
        "Ed25519Signature2018",
        "EcdsaSecp256k1Signature2019",
        "RsaSignature2018"
      ]
    },
    "ldp_vp": {
      "proof_type": ["Ed25519Signature2018"]
    },
    "ldp": {
      "proof_type": ["RsaSignature2018"]
    }
  },
  "input_descriptors":[
    {
      "id":"banking_input",
      "name":"Bank Account Information",
      "purpose":"We need your bank and account information.",
      "schema":[
        {
          "uri":"https://bank-standards.com/customer.json"
        }
      ],
      "constraints":{
        "limit_disclosure":true,
        "fields":[
          {
            "path":[
              "$.issuer",
              "$.vc.issuer",
              "$.iss"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "pattern":"did:example:123|did:example:456"
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input",
      "name":"US Passport",
      "schema":[
        {
          "uri":"hub://did:foo:123/Collections/schema.us.gov/passport.json"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.credentialSubject.birth_date",
              "$.vc.credentialSubject.birth_date",
              "$.birth_date"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "minimum":"1999-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_2 = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name":"Citizenship Information",
      "rule":"pick",
      "count":1,
      "from":"A"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://eu.com/claims/DriversLicense.json"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer",
              "$.vc.issuer",
              "$.iss"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "pattern":"did:example:gov1|did:example:gov2|https://example.edu/issuers/565049"
            }
          },
          {
            "path":[
              "$.credentialSubject.dob",
              "$.vc.credentialSubject.dob",
              "$.dob"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"1999-6-15"
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"hub://did:foo:123/Collections/schema.us.gov/passport.json"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.credentialSubject.birth_date",
              "$.vc.credentialSubject.birth_date",
              "$.birth_date"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"1999-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_3 = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name":"Banking Information",
      "purpose":"We need to know if you have an established banking history.",
      "rule":"pick",
      "count":1,
      "from":"A"
    },
    {
      "name":"Employment Information",
      "purpose":"We need to know that you are currently employed.",
      "rule":"all",
      "from":"B"
    },
    {
      "name":"Citizenship Information",
      "rule":"pick",
      "count":1,
      "from":"C"
    }
  ],
  "input_descriptors":[
    {
      "id":"banking_input_1",
      "name":"Bank Account Information",
      "purpose":"We need your bank and account information.",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://bank-standards.com/customer.json"
        }
      ],
      "constraints":{
        "limit_disclosure":true,
        "fields":[
          {
            "path":[
              "$.issuer",
              "$.vc.issuer",
              "$.iss"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "pattern":"did:example:123|did:example:456"
            }
          },
          {
            "path":[
              "$.credentialSubject.account[*].account_number",
              "$.vc.credentialSubject.account[*].account_number",
              "$.account[*].account_number"
            ],
            "purpose":"We need your bank account number for processing purposes",
            "filter":{
              "type":"string",
              "minLength":10,
              "maxLength":12
            }
          },
          {
            "path":[
              "$.credentialSubject.account[*].routing_number",
              "$.vc.credentialSubject.account[*].routing_number",
              "$.account[*].routing_number"
            ],
            "purpose":"You must have an account with a German, US, or Japanese bank account",
            "filter":{
              "type":"string",
              "pattern":"^DE|^US|^JP"
            }
          }
        ]
      }
    },
    {
      "id":"banking_input_2",
      "name":"Bank Account Information",
      "purpose":"We need your bank and account information.",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://bank-schemas.org/1.0.0/accounts.json"
        },
        {
          "uri":"https://bank-schemas.org/2.0.0/accounts.json"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer",
              "$.vc.issuer",
              "$.iss"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "pattern":"did:example:123|did:example:456"
            }
          },
          {
            "path":[
              "$.credentialSubject.account[*].id",
              "$.vc.credentialSubject.account[*].id",
              "$.account[*].id"
            ],
            "purpose":"We need your bank account number for processing purposes",
            "filter":{
              "type":"string",
              "minLength":10,
              "maxLength":12
            }
          },
          {
            "path":[
              "$.credentialSubject.account[*].route",
              "$.vc.credentialSubject.account[*].route",
              "$.account[*].route"
            ],
            "purpose":"You must have an account with a German, US, or Japanese bank account",
            "filter":{
              "type":"string",
              "pattern":"^DE|^US|^JP"
            }
          }
        ]
      }
    },
    {
      "id":"employment_input",
      "name":"Employment History",
      "purpose":"We need to know your work history.",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://business-standards.org/schemas/employment-history.json"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.jobs[*].active"
            ],
            "filter":{
              "type":"boolean",
              "pattern":"true"
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "C"
      ],
      "schema":[
        {
          "uri":"https://eu.com/claims/DriversLicense.json"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer",
              "$.vc.issuer",
              "$.iss"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "pattern":"did:example:gov1|did:example:gov2"
            }
          },
          {
            "path":[
              "$.credentialSubject.dob",
              "$.vc.credentialSubject.dob",
              "$.dob"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "minimum":"1999-5-16"
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "C"
      ],
      "schema":[
        {
          "uri":"hub://did:foo:123/Collections/schema.us.gov/passport.json"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.credentialSubject.birth_date",
              "$.vc.credentialSubject.birth_date",
              "$.birth_date"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "minimum":"1999-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

# pd_dict_list.append(json.loads(pres_exch_1))
pd_dict_list.append(json.loads(pres_exch_2))
# pd_dict_list.append(json.loads(pres_exch_3))
