# 🔒 Zero-Trust Corporate Gateway Configuration Blueprint

An enterprise-grade JSON Schema asset engineered to model, govern, and validate corporate edge gateway configuration profiles and security topologies. This framework establishes strict runtime security guardrails, validating structural data invariants for modern zero-trust hybrid network environments.

## 📐 Gateway Architecture Flow

```text
       [ Git Commit / Push ] ──► [ GitHub Actions CI/CD ] 
                                    │
                                    ▼
                       [ Virtual Ubuntu Runner ]
                                    │
                                    ▼
                      [ AJV Strict-Mode Compiler ]
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    │             CorporateGatewayInfrastructureSchema              │
    │  ───────────────────────────────────────────────────────────  │
    │  • Enforces Production Draft-07 Schema Specification          │
    │  • Evaluates Strict IPv4 CIDR Blocks via Regex Engines        │
    │  • Mutually Exclusive Auth Checking (JWT vs mTLS)             │
    │  • Dynamic Production Invariant Strict-Type Enforcement       │
    └───────────────────────────────┬───────────────────────────────┘
                                    │
            ┌───────────────────────┴───────────────────────┐
            │                                               │
            ▼ (Exit Code 0)                                 ▼ (Exit Code 1)
   [ ✅ VALIDATED STATE ]                          [ ❌ COMPILATION FAILURE ]
            │                                               │
            ▼                                               ▼
   [ Deploy to Infrastructure ]                    [ Build Terminated / Dropped ]
```
---

## 🧠 Core Engineering Challenges & Architectural Solutions

This infrastructure configuration schema solves three prominent security state issues faced by network engineering and DevOps automation teams:

### 1. The Multi-Topology Authentication Conflict
* **The Problem:** Edge architectures typically implement either centralized Token-based authentication (JWT) or decentralized cryptographic client certificate validation (mTLS). Accidental drift that populates both configurations simultaneously creates a non-deterministic routing state where security layers can be bypassed or misdirected.
* **The Solution:** Leveraged a strict `oneOf` strategy combined with internal object constraints. This makes the configuration architecturally mutually exclusive: establishing a `jwt_config` object instantly invalidates the presence of `mtls_config`, guaranteeing a single, deterministic security posture at runtime.

### 2. Environmental Compliance Drift & Type Laxity
* **The Problem:** Engineers require loose security parameters during local development and testing (e.g., bypassing HTTPS/HSTS requirements, omitting formal compliance logging). However, migrating these relaxed profiles directly into a live environment introduces massive compliance and security vulnerabilities. Furthermore, dynamic conditional blocks often bypass strict validation if the runtime type isn't explicitly pinned down.
* **The Solution:** Implemented an enterprise `if/then` conditional validation block nested inside a global `allOf` array using the **Draft-07 specification**. The moment the environment token is set to `"production"`, the gateway configuration checker dynamically morphs its validation criteria—instantly mandating an active `compliance_signoff` matrix. To comply with enterprise-grade **AJV Strict Mode**, the `then` clause explicitly enforces a `"type": "object"` constraint on the nested blocks, preventing runtime schema bypassing or implicit type guessing.

### 3. Syntax Laxity in Cryptographic Signatures & IP Invariants
* **The Problem:** Standard string checkers accept malformed subnet ranges or typo-ridden certificate thumbprints, failing silently until runtime routers crash or drop active customer traffic.
* **The Solution:** Embedded low-level regular expression engines directly inside the configuration types. The `ip_whitelist` array enforces formal IPv4 CIDR notation (`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[12]?[0-9])$`), and the `ca_certificate_thumbprint` restricts inputs strictly to a 40-character hexadecimal SHA-1 string, eliminating malformed text injections before they can reach the edge routers.

---

## 🛡️ Data Validation Layer

The structural integrity of the corporate gateway infrastructure is governed by a production-hardened JSON Schema using the **Draft-07 specification**. The schema operates under enterprise-grade **AJV Strict-Mode constraints**, ensuring that implicit type casting, unmapped keywords, and syntax ambiguities are blocked at compilation time.

### 📄 Hardened Configuration Schema (`corporate-gateway-schema.json`)
```
{
  "$schema": "http://json-schema.org/draft-07/schema#",
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
                "issuer": { "type": "string" },
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
            "type": "object",
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

### 🔍 Deep-Dive Structural Breakdown

* **Root Registration Strategy:** To bypass the historical "shortsightedness" of Draft-07's `"additionalProperties": false` constraint, all fundamental JSON objects (`network_security`, `auth_topology`) are explicitly registered under the root `properties` map. This enables sub-conditional evaluation blocks to append deep validation rules without injecting unregistered, top-level keys.
* **Deterministic Authentication Routing:** Using a `oneOf` array matched with explicit logical `not` constraints blocks the configuration from defining `jwt_config` and `mtls_config` simultaneously. This prevents edge nodes from encountering non-deterministic routing security states.
* **Strict Type Assertions:** In accordance with modern pipeline compilation standards, conditional `then` statements inject a mandatory `"type": "object"` clause at the target node path. This prevents the parser engine from attempting implicit structural inferences or skipping nested attribute scans.

---

## 📊 System Validation Matrix

The validation matrix below maps our test profiles against the explicit logic engines built into the infrastructure schema, demonstrating comprehensive positive and negative test coverage within the automated testing suite:

| Test File | Target Coordinate | Input Payload State | Expected Outcome | Active Constraint Evaluated |
| :--- | :--- | :--- | :--- | :--- |
| `valid_gateway_profile.json` | `gateway_id` | `"GW-USA-2026"` | **🟢 PASS** | Validated against strict string regex topology mapping (`^GW-[A-Z]{3}-[0-9]{4}$`). |
| `valid_gateway_profile.json` | `network_security.ip_whitelist` | Subnets inside valid IPv4 ranges | **🟢 PASS** | Array evaluations matching mathematical CIDR syntax limits. |
| `valid_gateway_profile.json` | `network_security` | `hsts_enabled: true` + active compliance signoff | **🟢 PASS** | Satisfies conditional `allOf -> if/then` block invariants for production environments. |
| `invalid_gateway_profile.json` | `network_security.ip_whitelist[0]` | `"999.999.999.999/99"` | **🔴 FAIL** | Value exceeds structural boundaries of IPv4 octets and CIDR masks. |
| `invalid_gateway_profile.json` | `network_security` | `environment: "production"` with missing `compliance_signoff` | **🔴 FAIL** | Blocked by conditional production guardrails (`#/allOf/0/then/properties/network_security/required`). |
| `invalid_gateway_profile.json` | `auth_topology` | Declares both `jwt_config` and `mtls_config` simultaneously | **🔴 FAIL** | Blocked by logical validation exclusion rules enforcing deterministic routing (`oneOf`). |
---

## 🌐 Semantic Graph Architecture

While the JSON Schema layer governs dynamic validation constraints at the execution edge, the enterprise framework maintains a **Semantic Twin** using W3C Resource Description Framework (RDF) standards expressed in the **Turtle (.ttl) dialect**. This transforms structural configuration payloads into an interconnected, queryable knowledge graph for organizational visibility.

### 🧠 Ontological Design (TBox vs. ABox)

The semantic architecture enforces a strict logical separation between definition and assertion:
* **The TBox (Terminology Box):** Establishes the structural ontology. It defines core classes (`sec:Gateway`, `sec:SecurityProfile`) and foundational properties (`sec:enforcesAuth`, `sec:hasSecurityProfile`), explicitly mapping out the permissible entity relationships and domain/range data boundaries.
* **The ABox (Assertion Box):** Contains the actual instance data triples. It populates the graph with concrete network assets (`corp:GW-USA-2026`) that mirror the exact valid configuration properties verified by the automated testing pipeline.

### 📄 Semantic Topology Mapping (`gateway-topology.ttl`)

```
@prefix rdf:   <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs:  <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
@prefix sec:   <http://enterprise.security.internal/ontology#> .
@prefix corp:  <http://enterprise.security.internal/infrastructure#> .

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
sec:gatewayId rdf:type rdf:Property ;
    rdfs:domain sec:Gateway ;
    rdfs:range xsd:string .

sec:environment rdf:type rdf:Property ;
    rdfs:domain sec:Gateway ;
    rdfs:range xsd:string .

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

sec:issuer rdf:type rdf:Property ;
    rdfs:domain sec:AuthTopology ;
    rdfs:range xsd:anyURI .

sec:algorithm rdf:type rdf:Property ;
    rdfs:domain sec:AuthTopology ;
    rdfs:range xsd:string .

### 3. ACTUAL GRAPH DATA (The Instances / Triples)
corp:GW-USA-2026 rdf:type sec:Gateway ;
    sec:gatewayId "GW-USA-2026"^^xsd:string ;
    sec:environment "production"^^xsd:string ;
    sec:hasSecurityProfile corp:ProductionSecProfile ;
    sec:enforcesAuth corp:JWT-EdgeStrategy .

corp:ProductionSecProfile rdf:type sec:SecurityProfile ;
    sec:hstsEnabled "true"^^xsd:boolean ;
    sec:complianceSignoff "ISO-27001-SEC99"^^xsd:string ;
    sec:ipWhitelist "10.0.0.0/8"^^xsd:string , "192.168.1.100/32"^^xsd:string .

corp:JWT-EdgeStrategy rdf:type sec:AuthTopology ;
    sec:issuer "https://auth.corporate-gateway.internal"^^xsd:anyURI ;
    sec:algorithm "RS256"^^xsd:string .
```

### 🎯 Data Graph Alignment Invariants

* **Schema Invariant Symmetry:** Structural pillars required by the JSON validator—such as `gateway_id` and `environment`—are explicitly mapped as distinct datatype predicates (`sec:gatewayId`, `sec:environment`) with defined `xsd:string` ranges. This guarantees the graph is a mathematically true representation of the JSON data state.
* **Semantic Type Preservation:** While the runtime validation layer utilizes streamlined string checking to maintain AJV compliance, the graph layer retains high-fidelity semantics. For instance, `sec:issuer` explicitly mandates an `xsd:anyURI` type cast, preserving rich metadata validation values for graph queries and SPARQL dependency checking.

