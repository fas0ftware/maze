from conftest import LAYER1, LAYER2, layer_of, login, outcome_of


def test_no_exit_on_layer_one(client):
    r = client.post("/exit", data={})
    assert outcome_of(r) == "exit_unavailable" and layer_of(r) == 1


def test_exit_form_asks_for_previous_layers(client):
    login(client, LAYER1)
    login(client, LAYER2)
    r = client.get("/exit")
    assert b'name="layer1"' in r.data and b'name="layer2"' in r.data


def test_exit_denied_with_wrong_passwords(client):
    login(client, LAYER1)
    login(client, LAYER2)
    r = client.post("/exit", data={"layer1": LAYER1, "layer2": "wrong"})
    assert outcome_of(r) == "exit_denied" and layer_of(r) == 3


def test_exit_requires_the_exact_decoy_used(client):
    """Another valid layer-1 decoy is not enough; it must be the one the session used."""
    login(client, LAYER1)
    r = client.post("/exit", data={"layer1": "letmein"})
    assert outcome_of(r) == "exit_denied"


def test_exit_granted_sends_back_to_start(client):
    login(client, LAYER1)
    login(client, LAYER2)
    r = client.post("/exit", data={"layer1": LAYER1, "layer2": LAYER2})
    assert outcome_of(r) == "exit_granted" and layer_of(r) == 1
    # The loop starts over: the layer-2 decoy no longer works.
    assert layer_of(login(client, LAYER2)) == 1


def test_exit_from_layer_two_needs_only_layer_one(client):
    login(client, LAYER1)
    r = client.post("/exit", data={"layer1": LAYER1})
    assert outcome_of(r) == "exit_granted"
