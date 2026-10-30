"""Visual Tester güvenlik regresyon testi şablonu — Pytest.

Üç yol (kullanılmayanları silin):
  (A) Django test client  (B) FastAPI TestClient / Flask test_client  (C) çalışan test sunucusu (VT_BASE_URL + httpx/requests)
{{...}} yer tutucularını doldurun. Test adı bulgu kimliğini içerir: rapordan izlenebilir.
"""
import os

import pytest

BASE = os.environ.get("VT_BASE_URL", "http://localhost:8000")
FINDING = "{{FINDING_ID}}"


# ---------------------------------------------------------------- (A) Django
# from django.contrib.auth import get_user_model
#
# @pytest.fixture
# def users(db):
#     User = get_user_model()
#     a = User.objects.create_user("a", "a@test.local", "pw-a")
#     b = User.objects.create_user("b", "b@test.local", "pw-b")
#     return a, b
#
# def test_vt_idor_django(client, users):
#     a, b = users
#     obj = Order.objects.create(owner=a, total=10)
#     client.force_login(b)
#     assert client.get(f"/api/orders/{obj.pk}/").status_code in (403, 404)
#     client.force_login(a)
#     assert client.get(f"/api/orders/{obj.pk}/").status_code == 200


# ---------------------------------------------------------------- (B) FastAPI
# from fastapi.testclient import TestClient
# from app.main import app
# client = TestClient(app)


# ---------------------------------------------------------------- (C) HTTP
httpx = pytest.importorskip("httpx")


def login(email: str, password: str) -> httpx.Client:
    c = httpx.Client(base_url=BASE, follow_redirects=False, timeout=10)
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code in (200, 204, 302), f"giriş başarısız: {r.status_code}"
    return c


@pytest.fixture(scope="module")
def user_a():
    return login("a@test.local", os.environ.get("VT_USER_A_PASS", "test-password-a"))


@pytest.fixture(scope="module")
def user_b():
    return login("b@test.local", os.environ.get("VT_USER_B_PASS", "test-password-b"))


def test_security_idor(user_a, user_b):
    """{{FINDING_ID}}: B, A'nın kaydını göremez."""
    assert user_b.get("{{ENDPOINT}}/{{OWNER_ID}}").status_code in (403, 404)
    assert user_a.get("{{ENDPOINT}}/{{OWNER_ID}}").status_code == 200


def test_security_bfla(user_a):
    """{{FINDING_ID}}: normal kullanıcı admin ucuna erişemez."""
    assert user_a.get("/api/admin/users").status_code in (401, 403, 404)
    anon = httpx.get(f"{BASE}/api/admin/users", follow_redirects=False)
    assert anon.status_code in (301, 302, 401, 403, 404)


def test_security_mass_assignment(user_a):
    """{{FINDING_ID}}: rol alanı istemciden değiştirilemez."""
    user_a.patch("/api/me", json={"display_name": "VT", "is_staff": True, "role": "admin"})
    me = user_a.get("/api/me").json()
    assert not me.get("is_staff") and me.get("role", "user") != "admin"


def test_security_ssti_and_xss(user_a):
    """{{FINDING_ID}}: şablon/HTML enjeksiyonu yansımaz."""
    r = user_a.get("/search", params={"q": "{{7*7}}VT <vt-x id=VT7f3a>"})
    assert "49VT" not in r.text
    assert "<vt-x id=VT7f3a>" not in r.text


def test_security_path_traversal(user_a):
    """{{FINDING_ID}}: indirme ucu proje dosyalarını vermez."""
    r = user_a.get("/download", params={"file": "../../requirements.txt"})
    assert r.status_code in (400, 403, 404)


def test_security_debug_off():
    """{{FINDING_ID}}: hata sayfası stack trace/debug bilgisi sızdırmaz."""
    r = httpx.get(f"{BASE}/vt-does-not-exist-%ff", follow_redirects=False)
    body = r.text.lower()
    assert "traceback" not in body and "werkzeug" not in body and "django version" not in body
