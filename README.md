# 🔒 Zero-Trust Corporate Gateway Configuration Blueprint

An enterprise-grade JSON Schema asset engineered to model, govern, and validate corporate edge gateway configuration topologies. This framework establishes strict runtime security guardrails, validating structural data invariants for modern zero-trust hybrid network environments.

## 📐 Gateway Architecture Flow

```text
       [ Edge Configuration Profile ]
                     │
                     ▼
       [ SecOps Gateway Engine Core ]
                     │
                     ▼
    ┌────────────────────────────────────────┐
    │  CorporateGatewayInfrastructureSchema  │
    │  ────────────────────────────────────  │
    │  • Validates Gateway ID Topologies     │
    │  • Evaluates Strict IPv4 CIDR Blocks   │
    │  • Mutually Exclusive Auth Checking    │
    │  • Dynamic Production Invariant Rules  │
    └────────────────────────────────────────┘
                     │
            ┌────────┴────────┐
            │                 │
            ▼                 ▼
   [ HARDENED STATE ]  [ RULE VIOLATION ]
            │                 │
            ▼                 ▼
    [ Apply Topology ] [ Configuration Drop ]
```
---

## 🧠 Core Engineering Challenges & Architectural Solutions

This infrastructure configuration schema solves three prominent security state issues faced by network engineering and DevOps automation teams:

### 1. The Multi-Topology Authentication Conflict
* **The Problem:** Edge architectures typically implement either centralized Token-based authentication (JWT) or decentralized cryptographic client certificate validation (mTLS). Accidental drift that populates both configurations simultaneously creates a non-deterministic routing state where security layers can be bypassed or misdirected.
* **The Solution:** Leveraged a strict `oneOf` strategy combined with internal `not` dependencies. This makes the configuration architecturally mutually exclusive: establishing a `jwt_config` object instantly invalidates the presence of `mtls_config`, guaranteeing a single, deterministic security posture at runtime.

### 2. Environmental Compliance Drift
* **The Problem:** Engineers require loose security parameters during local development and testing (e.g., bypassing HTTPS/HSTS requirements, omitting formal compliance logging). However, migrating these relaxed profiles directly into a live environment introduces massive compliance and security vulnerabilities.
* **The Solution:** Implemented an enterprise `if/then` conditional validation block nested inside a global `allOf` array. The moment an engineer modifies the `environment` token to `"production"`, the gateway configuration checker dynamically morphs its validation criteria—instantly mandating an active `compliance_signoff` matrix and enforcing that `hsts_enabled` is explicitly set to `true`.

### 3. Syntax Laxity in Cryptographic Signatures & IP Invariants
* **The Problem:** Standard string checkers accept malformed subnet ranges or typo-ridden certificate thumbprints, failing silently until runtime routers crash or drop active customer traffic.
* **The Solution:** Embedded low-level regular expression engines directly inside the configuration types. The `ip_whitelist` array enforces formal IPv4 CIDR notation (`^((25[0-5]|2[0-4][0-9]...)/(3[0-2]|[12]?[0-9])$`), and the `ca_certificate_thumbprint` restricts inputs strictly to a 40-character hexadecimal SHA-1 string.

---

## 📜 Production Schema Engine

The complete, production-ready enterprise JSON Schema validating zero-trust edge topologies and environmental invariant compliance rules is embedded below:
```
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CorporateGatewayInfrastructureSchema",
  "description": "Validates enterprise zero-trust gateway access configuration profiles and security topologies.",
  "type": "object",
  "required": ["gateway_id", "environment", "network_security", "auth_topology"],
  "additionalProperties": false,
  "properties": {
    "gateway_id": {
      "type": "string",
      "pattern": "^GW-[A-Z]{3}-[0-9]{4}$"
    },
    "environment": {
      "type": "string",
      "enum": ["development", "staging", "production"]
    },
    "network_security": {
      "type": "object",
      "required": ["ip_whitelist", "hsts_enabled"],
      "additionalProperties": false,
      "properties": {
        "ip_whitelist": {
          "type": "array",
          "items": {
            "type": "string",
            "pattern": "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[12]?[0-9])$"
          }
        },
        "hsts_enabled": { "type": "boolean" },
        "compliance_signoff": {
          "type": "array",
          "items": { "type": "string", "pattern": "^ISO-27001-[A-Z0-9]{5}$" },
          "minItems": 1
        }
      }
    },
    "auth_topology": {
      "type": "object",
      "oneOf": [
        {
          "required": ["jwt_config"],
          "properties": {
            "jwt_config": {
              "type": "object",
              "required": ["issuer", "algorithm"],
              "additionalProperties": false,
              "properties": {
                "issuer": { "type": "string", "format": "uri" },
                "algorithm": { "type": "string", "enum": ["RS256", "ES256"] }
              }
            }
          },
          "not": { "required": ["mtls_config"] }
        },
        {
          "required": ["mtls_config"],
          "properties": {
            "mtls_config": {
              "type": "object",
              "required": ["ca_certificate_thumbprint", "enforce_revocation_check"],
              "additionalProperties": false,
              "properties": {
                "ca_certificate_thumbprint": { "type": "string", "pattern": "^[a-fA-F0-9]{40}$" },
                "enforce_revocation_check": { "type": "boolean" }
              }
            }
          },
          "not": { "required": ["jwt_config"] }
        }
      ]
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "environment": { "const": "production" }
        }
      },
      "then": {
        "properties": {
          "network_security": {
            "required": ["compliance_signoff"],
            "properties": {
              "hsts_enabled": { "const": true }
            }
          }
        }
      }
    }
  ]
}
```
---

## 📊 System Validation Matrix

The validation matrix below maps our test profiles against the explicit logic engines built into the infrastructure schema:

| Test File | Target Coordinate | Input Payload State | Expected Outcome | Active Constraint Evaluated |
| :--- | :--- | :--- | :--- | :--- |
| `valid_gateway_profile.json` | `gateway_id` | `"GW-USA-2026"` | **PASS** | Validated against string regex topology mapping |
| `valid_gateway_profile.json` | `ip_whitelist` | Subnets inside valid IPv4 ranges | **PASS** | Array evaluations matching CIDR syntax limits |
| `valid_gateway_profile.json` | `network_security` | `hsts_enabled: true` + active compliance signoff | **PASS** | Satisfies conditional `allOf` block for production environments |
| `invalid_gateway_profile.json` | `ip_whitelist[0]` | `"999.999.999.999/99"` | **FAIL** | Values exceed mathematical boundaries of IPv4 octets and CIDR masks |
| `invalid_gateway_profile.json` | `network_security` | `environment: "production"` with HSTS disabled | **FAIL** | Blocked by conditional invariant matching rule |
| `invalid_gateway_profile.json` | `auth_topology` | Declares both `jwt_config` and `mtls_config` | **FAIL** | Blocked by logical validation exclusion (`oneOf` mutual exclusivity rule) |

---

## 🕸️ Semantic Ontology Layer (Linked Data Transformation)

While hierarchical structures like JSON are optimal for edge validation gates, modern enterprise architectures leverage semantic graphs to govern unified infrastructure states. Below is the semantic mapping of our valid gateway topology, abstracted into absolute atomic triples using **Turtle (RDF) syntax**:

```turtle
@prefix rdf:   [http://www.w3.org/1999/02/22-rdf-syntax-ns#](http://www.w3.org/1999/02/22-rdf-syntax-ns#) .
@prefix rdfs:  [http://www.w3.org/2000/01/rdf-schema#](http://www.w3.org/2000/01/rdf-schema#) .
@prefix xsd:   [http://www.w3.org/2001/XMLSchema#](http://www.w3.org/2001/XMLSchema#) .
@prefix sec:   [http://enterprise.security.internal/ontology#](http://enterprise.security.internal/ontology#) .
@prefix corp:  [http://enterprise.security.internal/infrastructure#](http://enterprise.security.internal/infrastructure#) .

### 1. CONCEPT DEFINITIONS (The Schema / Classes)
sec:Gateway rdf:type rdfs:Class ;
    rdfs:subClassOf rdfs:Resource ;
    rdfs:label "Security Gateway" ;
    rdfs:comment "An edge gateway enforcing zero-trust access policies." .

sec:SecurityProfile rdf:type rdfs:Class ;
    rdfs:subClassOf rdfs:Resource ;
    rdfs:label "Network Security Profile" .

sec:AuthTopology rdf:type rdfs:Class ;
    rdfs:subClassOf rdfs:Resource ;
    rdfs:label "Authentication Topology Strategy" .

### 2. RELATIONSHIP DEFINITIONS (The Predicates / Properties)
sec:hasSecurityProfile rdf:type rdf:Property ;
    rdfs:domain sec:Gateway ;
    rdfs:range sec:SecurityProfile .

sec:enforcesAuth rdf:type rdf:Property ;
    rdfs:domain sec:Gateway ;
    rdfs:range sec:AuthTopology .

sec:hstsEnabled rdf:type rdf:Property ;
    rdfs:domain sec:SecurityProfile ;
    rdfs:range xsd:boolean .

sec:complianceSignoff rdf:type rdf:Property ;
    rdfs:domain sec:SecurityProfile ;
    rdfs:range xsd:string .

sec:ipWhitelist rdf:type rdf:Property ;
    rdfs:domain sec:SecurityProfile ;
    rdfs:range xsd:string .

### 3. ACTUAL GRAPH DATA (The Instances / Triples)
corp:GW-USA-2026 rdf:type sec:Gateway ;
    sec:hasSecurityProfile corp:ProductionSecProfile ;
    sec:enforcesAuth corp:JWT-EdgeStrategy .

corp:ProductionSecProfile rdf:type sec:SecurityProfile ;
    sec:hstsEnabled "true"^^xsd:boolean ;
    sec:complianceSignoff "ISO-27001-SEC99"^^xsd:string ;
    sec:ipWhitelist "10.0.0.0/8"^^xsd:string , "192.168.1.100/32"^^xsd:string .

corp:JWT-EdgeStrategy rdf:type sec:AuthTopology ;
    sec:issuer "[https://auth.corporate-gateway.internal](https://auth.corporate-gateway.internal)"^^xsd:anyURI ;
    sec:algorithm "RS256"^^xsd:string .
