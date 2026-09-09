# Provenance Record: NIST SP 800-171 Rev 2 to NIST SP 800-53 Rev 5 Ground Truth Mapping

## 1. Exact URL / Endpoint(s)
The authoritative machine-readable mapping table was fetched directly from the **NIST Cybersecurity and Privacy Reference Tool (CPRT)** REST API endpoints:
- **Requirement Elements Index URL**:  
  `https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_2_0_0/type/requirement/elements`
- **Control Relationship Graph URL Pattern**:  
  `https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_2_0_0/element/{element_id}/graph`
- **CPRT Relationship Detail URL Pattern**:  
  `https://csrc.nist.gov/extensions/nudp/services/json/nudp/cprt-relationship/{relationshipIdentifier}`
- **CPRT Portal Base URL**:  
  `https://csrc.nist.gov/projects/cprt` (Catalog: `https://csrc.nist.gov/Projects/cprt/catalog`)

## 2. Publisher
**National Institute of Standards and Technology (NIST)**  
U.S. Department of Commerce  
Computer Security Division, Information Technology Laboratory (ITL)

## 3. Authority
**NIST-authoritative**  
Published and maintained directly by NIST as part of the official CPRT (Cybersecurity and Privacy Reference Tool) and OLIR (Online Informative References) program (`focalDocTemplateName`: `"NIST SP 800-171 R2 to NIST SP 800-53 R5"`).

## 4. Format
**JSON** (Machine-readable, structured REST API data model containing full relationship edge records, focal/reference control identifiers, rationale descriptions, set type descriptions, and control statement texts).

## 5. Control Coverage & Statistics
- **Total SP 800-171 Rev 2 Controls Covered**: **110 controls** (all requirements from 3.1.1 through 3.14.7).
- **Controls with SP 800-53 Rev 5 Mapping**: **109 controls**.
- **Controls without SP 800-53 Rev 5 Mapping**: **1 control** (`3.13.14` - "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.", which has no mapped entry in NIST's CPRT dataset).
- **Total Mapping Edges (Relationships)**: **150 control-to-control relationship edges**.
