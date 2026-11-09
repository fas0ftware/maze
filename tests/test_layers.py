from conftest import LAYER1, LAYER2, TEST_REAL_PASSWORD, layer_of, login, outcome_of


def test_starts_at_layer_one(client):
    assert layer_of(client.get("/")) == 1


def test_wrong_password_stays_on_layer_one(client):
    r = login(client, "nope")
    assert r.status_code == 401
    assert layer_of(r) == 1
    assert outcome_of(r) == "wrong"


def test_layer2_decoy_does_not_work_on_layer1(client):
    assert layer_of(login(client, LAYER2)) == 1


def test_decoys_advance_layers(client):
    r = login(client, LAYER1)
    assert layer_of(r) == 2 and b"First password found" in r.data
    r = login(client, LAYER2)
    assert layer_of(r) == 3 and b"Second password found" in r.data


def test_real_password_is_rejected_before_layer_three(client):
    r = login(client, TEST_REAL_PASSWORD)
    assert layer_of(r) == 1 and outcome_of(r) == "wrong"


def test_real_password_on_layer_three(client):
    login(client, LAYER1)
    login(client, LAYER2)
    r = login(client, TEST_REAL_PASSWORD)
    assert r.status_code == 200 and outcome_of(r) == "real_success"


def test_wrong_password_on_layer_three(client):
    login(client, LAYER1)
    login(client, LAYER2)
    r = login(client, "definitely-wrong")
    assert r.status_code == 401 and outcome_of(r) == "wrong" and layer_of(r) == 3


def test_decoy_is_wrong_on_layer_three(client):
    login(client, LAYER1)
    login(client, LAYER2)
    assert outcome_of(login(client, LAYER1)) == "wrong"


def test_state_is_per_session(app):
    a, b = app.test_client(), app.test_client()
    login(a, LAYER1)
    assert layer_of(a.get("/")) == 2
    assert layer_of(b.get("/")) == 1
