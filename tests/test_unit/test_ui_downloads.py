from app import _build_attack_flow_stages, _build_demo_security_state
from security_incident_management import build_executive_report, render_executive_report_pdf


def test_build_and_render_executive_report_bytes():
    demo = _build_demo_security_state()
    cases = demo.get("cases", [])
    report = build_executive_report(
        demo, cases, demo.get("attacks", []), demo.get("active", []), demo.get("blocked_ips", [])
    )
    assert isinstance(report, dict)
    pdf = render_executive_report_pdf(report)
    assert isinstance(pdf, (bytes, bytearray))
    assert pdf.startswith(b"%PDF")


def test_attack_flow_stages_have_expected_structure():
    stages = _build_attack_flow_stages()
    assert isinstance(stages, list)
    assert all(isinstance(s, dict) for s in stages)
    # must include stage keys
    for s in stages:
        assert "stage" in s and "status" in s and "control" in s
