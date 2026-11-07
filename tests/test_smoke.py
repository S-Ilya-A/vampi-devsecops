"""Smoke tests for the API. Need a database: DATABASE_URL (Postgres in CI) or the SQLite fallback."""
import pytest

from config import vuln_app


@pytest.fixture(scope="module")
def client():
    c = vuln_app.app.test_client()
    r = c.get("/createdb")
    assert r.status_code == 200
    return c


def login(client, username, password):
    r = client.post("/users/v1/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return r.get_json()


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "VAmPI" in r.get_json()["message"]


def test_list_users(client):
    r = client.get("/users/v1")
    assert r.status_code == 200
    names = [u["username"] for u in r.get_json()["users"]]
    assert "admin" in names


def test_login_and_me(client):
    token = login(client, "name1", "pass1")["auth_token"]
    r = client.get("/me", headers={"Authorization": "Bearer " + token})
    assert r.status_code == 200
    assert r.get_json()["data"]["username"] == "name1"


def test_wrong_password_rejected(client):
    body = login(client, "name1", "wrong")
    assert body["status"] == "fail"


def test_books_listed(client):
    r = client.get("/books/v1")
    assert r.status_code == 200
    assert len(r.get_json()["Books"]) >= 3


def test_book_requires_token(client):
    r = client.get("/books/v1/anything")
    assert r.status_code == 401
