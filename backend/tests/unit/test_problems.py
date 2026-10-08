from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from securescan.api.problems import (
    Conflict,
    NotFound,
    Problem,
    UnprocessableEntity,
    install_problem_handlers,
)


class Body(BaseModel):
    name: str = Field(min_length=3)


def make_client() -> TestClient:
    app = FastAPI()
    install_problem_handlers(app)

    @app.get("/missing")
    async def missing() -> None:
        raise NotFound("Thing not found", code="thing.not_found")

    @app.get("/conflict")
    async def conflict() -> None:
        raise Conflict("Already there", code="thing.duplicate", headers={"X-Extra": "1"}, offset=5)

    @app.get("/rule")
    async def rule() -> None:
        raise UnprocessableEntity(
            "Production targets accept baseline scans only", code="dast.production_baseline_only"
        )

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("secret internal detail")

    @app.post("/validate")
    async def validate(body: Body) -> dict[str, str]:
        return {"name": body.name}

    return TestClient(app, raise_server_exceptions=False)


def test_not_found_is_problem_json() -> None:
    response = make_client().get("/missing")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["title"] == "Not Found"
    assert body["status"] == 404
    assert body["detail"] == "Thing not found"
    assert body["code"] == "thing.not_found"
    assert body["instance"] == "/missing"
    assert body["type"] == "urn:securescan:problem:not-found"


def test_extension_members_and_headers() -> None:
    response = make_client().get("/conflict")
    assert response.status_code == 409
    assert response.headers["x-extra"] == "1"
    assert response.json()["offset"] == 5


def test_rule_violation_carries_a_plain_words_detail() -> None:
    body = make_client().get("/rule").json()
    assert body["status"] == 422
    assert "baseline" in body["detail"]


def test_validation_errors_list_fields_without_input_values() -> None:
    response = make_client().post("/validate", json={"name": "x"})
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["code"] == "validation_error"
    assert body["errors"][0]["field"] == "body.name"
    assert '"x"' not in response.text.replace('"name"', "")


def test_unknown_route_is_problem_json() -> None:
    response = make_client().get("/nope")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")


def test_unhandled_error_hides_the_cause() -> None:
    response = make_client().get("/boom")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert "secret internal detail" not in response.text


def test_problem_to_dict_defaults() -> None:
    problem = Problem(status=418)
    body = problem.to_dict("/x")
    assert body["title"] == "I'm a Teapot"
    assert body["status"] == 418
    assert body["instance"] == "/x"
    assert "detail" not in body
