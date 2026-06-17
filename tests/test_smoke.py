from repo_scam_shield.main import scan


def test_scan_flags_suspicious_repo_url():
    result = scan("https://github.com/example/Spotify-Premium-Patcher-2026")
    assert result["risk"] in {"medium", "high"}
    assert result["score"] >= 30
    assert result["matches"]


def test_scan_clean_name_is_low_risk():
    result = scan("https://github.com/example/boring-docs")
    assert result["risk"] == "low"
