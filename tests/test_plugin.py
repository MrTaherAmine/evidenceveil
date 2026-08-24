from evidenceveil.plugins.example import ExampleTicketDetector


def test_example_plugin():
    p = ExampleTicketDetector()
    assert p.classify("incident.ticket", "INC-123") == "incident.ticket"
    assert p.classify("user.name", "alice") is None
