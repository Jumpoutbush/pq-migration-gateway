"""OpenAPI contract for the v3.7 API-first control plane."""
from __future__ import annotations


def _operation(summary: str, *, body: bool = False, body_schema: dict | None = None,
               success: str = "200", public: bool = False) -> dict:
    value: dict = {
        "summary": summary,
        "responses": {
            success: {
                "description": "Successful response",
                "content": {"application/json": {"schema": {"type": "object"}}},
            },
            "400": {"description": "Invalid request"},
            "401": {"description": "Bearer token required"},
            "409": {"description": "Lifecycle conflict"},
        },
    }
    if body or body_schema:
        value["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": body_schema or {"type": "object"}}},
        }
    if public:
        value["security"] = []
    return value


def document(server_url: str = "http://127.0.0.1:18080") -> dict:
    paths = {
        "/healthz": {"get": _operation("Manager API health", public=True)},
        "/metrics": {"get": _operation("Prometheus metrics", public=True)},
        "/openapi.json": {"get": _operation("OpenAPI contract", public=True)},
        "/v1/capabilities": {"get": _operation("Supported adapters, workflows and authorized scan roots")},
        "/v1/status": {"get": _operation("Aggregated control-plane and Gateway status")},
        "/v1/onboarding": {"post": _operation(
            "Validate, register and publish a Gateway service",
            body_schema={"$ref": "#/components/schemas/ServicePublishRequest"}, success="202",
        )},
        "/v1/services": {
            "get": _operation("List Gateway service resources"),
            "post": _operation("Create or update a service resource without publishing", body_schema={"$ref": "#/components/schemas/Service"}, success="201"),
        },
        "/v1/services/{service_id}": {
            "parameters": [{"name": "service_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get a Gateway service resource"),
            "put": _operation("Update a service resource without publishing", body=True),
            "delete": _operation("Delete a service resource without publishing"),
        },
        "/v1/services/{service_id}/publish": {
            "parameters": [{"name": "service_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "post": _operation("Atomically validate, update and stage a service release", body_schema={"$ref": "#/components/schemas/Service"}, success="202"),
        },
        "/v1/services/{service_id}/transition": {
            "parameters": [{"name": "service_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "post": _operation("Apply an audited migration-state transition", body=True),
        },
        "/v1/policies": {
            "get": _operation("List migration policy resources"),
            "post": _operation("Create or update a policy without publishing", body=True, success="201"),
        },
        "/v1/policies/{policy_id}": {
            "parameters": [{"name": "policy_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get a migration policy resource"),
            "put": _operation("Update a migration policy without publishing", body=True),
            "delete": _operation("Delete a migration policy without publishing"),
        },
        "/v1/scans": {
            "get": _operation("List enterprise scan jobs"),
            "post": _operation("Create an asynchronous enterprise scan", body_schema={"$ref": "#/components/schemas/ScanRequest"}, success="202"),
        },
        "/v1/scans/{scan_id}": {
            "parameters": [{"name": "scan_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get enterprise scan status"),
        },
        "/v1/scans/{scan_id}/findings": {
            "parameters": [{"name": "scan_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("List scan findings and interface evidence"),
        },
        "/v1/runtime/reports": {
            "post": _operation(
                "Submit an idempotent process/container runtime evidence batch",
                body_schema={"$ref": "#/components/schemas/RuntimeReport"}, success="202",
            ),
        },
        "/v1/runtime/agents": {"get": _operation("List Runtime Agents and freshness")},
        "/v1/runtime/agents/{agent_id}": {
            "parameters": [{"name": "agent_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get one Runtime Agent and its observed processes"),
        },
        "/v1/runtime/batches": {"get": _operation("List Runtime Agent ingestion batches")},
        "/v1/runtime/batches/{batch_id}": {
            "parameters": [{"name": "batch_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get one Runtime Agent ingestion batch"),
        },
        "/v1/runtime/observations": {"get": _operation("List normalized runtime library and crypto-call observations")},
        "/v1/assets": {"get": _operation("List normalized cryptographic assets")},
        "/v1/assets/{asset_id}": {
            "parameters": [{"name": "asset_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get an asset and its evidence"),
        },
        "/v1/assets/{asset_id}/assess": {
            "parameters": [{"name": "asset_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "post": _operation("Assess post-quantum migration risk", success="201"),
        },
        "/v1/assets/{asset_id}/migration": {
            "parameters": [{"name": "asset_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "post": _operation("Create, verify, promote or complete a migration plan", body_schema={"$ref": "#/components/schemas/MigrationRequest"}, success="202"),
        },
        "/v1/releases": {
            "get": _operation("List immutable configuration releases"),
            "post": _operation("Validate and stage a complete service document", body_schema={"$ref": "#/components/schemas/ReleaseDocument"}, success="202"),
        },
        "/v1/releases/validate": {"post": _operation("Validate a complete service document", body_schema={"$ref": "#/components/schemas/ReleaseDocument"})},
        "/v1/releases/from-resources": {"post": _operation("Stage all current service resources", body=True, success="202")},
        "/v1/releases/{version}": {
            "parameters": [{"name": "version", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "get": _operation("Get release lifecycle and status history"),
        },
        "/v1/releases/{version}/rollback": {
            "parameters": [{"name": "version", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "post": _operation("Stage a new release from an historical version", success="202"),
        },
        "/v1/agents": {"get": _operation("List Gateway Agents and health")},
        "/v1/agents/{agent_id}": {
            "parameters": [{"name": "agent_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get one Gateway Agent"),
        },
        "/v1/agents/{agent_id}/heartbeat": {
            "parameters": [{"name": "agent_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "post": _operation("Report Gateway Agent execution and health", body=True),
        },
        "/v1/migrations": {"get": _operation("List service migration states")},
        "/v1/migrations/{service_id}": {
            "parameters": [{"name": "service_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("Get one service migration state"),
        },
        "/v1/migrations/{service_id}/history": {
            "parameters": [{"name": "service_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": _operation("List audited migration-state transitions"),
        },
        "/v1/metrics": {"get": _operation("List control-plane metrics as JSON")},
        "/v1/audit": {"get": _operation("List immutable control-plane audit events")},
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "PQC Migration Gateway Manager API",
            "version": "3.7.0",
            "description": "API-first enterprise cryptographic discovery, migration release and rollback control plane.",
        },
        "servers": [{"url": server_url}],
        "security": [{"BearerAuth": []}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "opaque-token"},
            },
            "schemas": {
                "Service": {
                    "type": "object", "required": ["id", "listen", "upstream"],
                    "properties": {
                        "id": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"},
                        "adapter": {"type": "string", "default": "http"},
                        "listen": {
                            "type": "object", "required": ["port"],
                            "properties": {
                                "address": {"type": "string", "default": "0.0.0.0"},
                                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                                "server_name": {"type": "string"},
                            },
                        },
                        "downstream_tls": {"type": "object"},
                        "upstream": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "object", "required": ["address"], "properties": {
                                    "address": {"type": "string"}, "tls": {"type": "object"},
                                }},
                            ],
                        },
                        "timeouts": {"type": "object"},
                        "rollout": {"type": "object"},
                        "audit": {"type": "object"},
                        "protocol_options": {"type": "object"},
                    },
                },
                "ServicePublishRequest": {
                    "oneOf": [
                        {"$ref": "#/components/schemas/Service"},
                        {"type": "object", "required": ["service"], "properties": {
                            "service": {"$ref": "#/components/schemas/Service"},
                            "defaults": {"type": "object"},
                        }},
                    ],
                },
                "ReleaseDocument": {
                    "type": "object", "required": ["services"],
                    "properties": {
                        "schema_version": {"type": "string", "default": "4.0"},
                        "defaults": {"type": "object"},
                        "services": {"type": "array", "minItems": 1, "items": {"$ref": "#/components/schemas/Service"}},
                    },
                },
                "ScanRequest": {
                    "type": "object", "required": ["roots"],
                    "properties": {
                        "type": {"type": "string", "enum": ["enterprise"], "default": "enterprise"},
                        "roots": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                        "compile_commands": {"type": "array", "items": {"type": "string"}},
                        "cpp_semantic": {"type": "string", "enum": ["auto", "on", "off"], "default": "auto"},
                        "scan_processes": {"type": "boolean", "default": False},
                        "ebpf_trace": {"type": "string"},
                        "live_ebpf": {"type": "boolean", "default": False},
                    },
                },
                "RuntimeReport": {
                    "type": "object",
                    "required": ["schema_version", "batch_id", "collected_at", "agent", "processes", "observations"],
                    "properties": {
                        "schema_version": {"type": "integer", "enum": [1]},
                        "batch_id": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"},
                        "collected_at": {"type": "string"},
                        "agent": {
                            "type": "object", "required": ["id", "hostname", "version"],
                            "properties": {
                                "id": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$"},
                                "hostname": {"type": "string"}, "version": {"type": "string"},
                                "boot_id": {"type": "string"}, "mode": {"type": "string"},
                                "capabilities": {"type": "array", "items": {"type": "string"}},
                                "metadata": {"type": "object"},
                            },
                        },
                        "processes": {"type": "array", "maxItems": 5000, "items": {"type": "object"}},
                        "observations": {"type": "array", "maxItems": 20000, "items": {"type": "object"}},
                    },
                },
                "MigrationRequest": {
                    "type": "object", "required": ["action"],
                    "properties": {
                        "action": {"type": "string", "enum": ["create", "verify", "promote", "complete"]},
                        "service": {"$ref": "#/components/schemas/Service"},
                        "verification_result": {"type": "string"},
                        "fallback_rate": {"type": "number", "minimum": 0, "maximum": 1},
                        "fallback_threshold": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                },
            },
        },
        "paths": paths,
    }
