"""Tests for the ML anomaly pipeline: features, models, training, scoring."""

from datetime import UTC, datetime

import numpy as np
import pytest

from sentinelx.common.models import Event
from sentinelx.ml import features, sample_data, scoring
from sentinelx.ml.models import AutoencoderModel, IsolationForestModel
from sentinelx.ml.train import load_login_events, load_traffic_events, train_models


def _login_event_sets(tmp_path):
    normal_csv = tmp_path / "login_normal.csv"
    anom_csv = tmp_path / "login_anom.csv"
    sample_data.generate_login_csv(normal_csv, n_normal=400, n_anomalous=0, seed=7)
    sample_data.generate_login_csv(anom_csv, n_normal=0, n_anomalous=20, seed=7)
    return load_login_events(normal_csv), load_login_events(anom_csv)


def _traffic_event_sets(tmp_path):
    normal_csv = tmp_path / "traffic_normal.csv"
    anom_csv = tmp_path / "traffic_anom.csv"
    sample_data.generate_traffic_csv(normal_csv, n_normal=400, n_anomalous=0, seed=7)
    sample_data.generate_traffic_csv(anom_csv, n_normal=0, n_anomalous=20, seed=7)
    return load_traffic_events(normal_csv), load_traffic_events(anom_csv)


def test_login_features_shape_and_formulas():
    base = datetime(2026, 10, 16, 3, 0, 0, tzinfo=UTC)
    events = [
        Event(
            timestamp=base,
            host="h1",
            source="auth",
            event_type="authentication",
            src_ip=f"10.0.0.{i}",
            user="alice",
            action="login_failed",
        )
        for i in range(3)
    ]
    X = features.login_features(events)
    assert X.shape == (1, 5)
    # 03:00 is an unusual hour -> last column 1.0; 3 distinct src ips
    assert X[0, 4] == 1.0
    assert X[0, 3] == 3.0
    assert X[0, 2] == 3.0  # n_failed_last_20
    # cyclic encoding of hour 3: sin/cos of 2*pi*3/24
    assert X[0, 0] == pytest.approx(np.sin(2 * np.pi * 3 / 24))
    assert X[0, 1] == pytest.approx(np.cos(2 * np.pi * 3 / 24))


def test_traffic_features_shape_and_formulas():
    base = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
    events = [
        Event(
            timestamp=base,
            host="web1",
            source="nginx",
            event_type="web",
            http_method="GET",
            http_uri="/login",
            http_status=500 if i == 0 else 200,
        )
        for i in range(4)
    ]
    X = features.traffic_features(events)
    assert X.shape == (1, 4)
    assert X[0, 1] == pytest.approx(0.25)  # 1 of 4 is an error
    assert X[0, 3] == 1.0  # single distinct uri
    assert X[0, 2] > 0.0  # shannon entropy of "/login" chars


def test_uri_entropy_known_value():
    # "aaab": p(a)=.75, p(b)=.25 -> -(0.75*log2(0.75) + 0.25*log2(0.25))
    expected = -(0.75 * np.log2(0.75) + 0.25 * np.log2(0.25))
    assert features._uri_entropy(["aaab"]) == pytest.approx(expected)


@pytest.mark.parametrize("kind", ["login", "traffic"])
def test_anomalies_score_higher_than_normal_median(tmp_path, kind):
    if kind == "login":
        normal, anom = _login_event_sets(tmp_path)
        X_normal, X_anom = features.login_features(normal), features.login_features(anom)
    else:
        normal, anom = _traffic_event_sets(tmp_path)
        X_normal, X_anom = features.traffic_features(normal), features.traffic_features(anom)
    assert X_normal.shape[0] > 0 and X_anom.shape[0] > 0

    model = IsolationForestModel().fit(X_normal)
    normal_scores = model.score(X_normal)
    anom_scores = model.score(X_anom)
    assert np.median(anom_scores) > np.median(normal_scores)
    assert ((normal_scores >= 0) & (normal_scores <= 1)).all()

    auto = AutoencoderModel(max_iter=200).fit(X_normal)
    auto_anom = auto.score(X_anom)
    assert np.median(auto_anom) > np.median(auto.score(X_normal))
    assert ((auto_anom >= 0) & (auto_anom <= 1)).all()


def test_save_load_roundtrip_preserves_scores(tmp_path):
    normal, anom = _login_event_sets(tmp_path)
    X = features.login_features(normal)
    Xa = features.login_features(anom)
    for model in (IsolationForestModel().fit(X), AutoencoderModel(max_iter=200).fit(X)):
        path = tmp_path / "model.joblib"
        model.save(path)
        reloaded = type(model).load(path)
        np.testing.assert_allclose(reloaded.score(Xa), model.score(Xa), rtol=1e-6)


def test_score_event_end_to_end(tmp_path, monkeypatch):
    model_dir = tmp_path / "models"
    sample = tmp_path / "login.csv"
    sample_data.generate_login_csv(sample, n_normal=300, n_anomalous=0, seed=11)
    train_models("login", sample, model_dir)

    monkeypatch.setenv("SENTINELX_MODEL_DIR", str(model_dir))
    scoring._reset_cache()
    suspicious = Event(
        timestamp=datetime(2026, 10, 16, 3, 15, 0, tzinfo=UTC),
        host="ws01",
        source="auth",
        event_type="authentication",
        src_ip="198.51.100.9",
        user="mallory",
        action="login_failed",
    )
    score = scoring.score_event(suspicious)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0

    normal = Event(
        timestamp=datetime(2026, 10, 16, 10, 15, 0, tzinfo=UTC),
        host="ws01",
        source="auth",
        event_type="authentication",
        src_ip="10.0.1.7",
        user="user0001",
        action="login_success",
    )
    normal_score = scoring.score_event(normal)
    assert 0.0 <= normal_score <= 1.0
    assert score > normal_score  # 3am brute-force looks more anomalous


def test_score_event_no_models_returns_zero(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("SENTINELX_MODEL_DIR", str(empty))
    scoring._reset_cache()
    event = Event(
        timestamp=datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC),
        host="h",
        source="auth",
        event_type="authentication",
    )
    assert scoring.score_event(event) == 0.0


def test_train_cli_files_exist(tmp_path):
    sample = tmp_path / "traffic.csv"
    sample_data.generate_traffic_csv(sample, n_normal=300, n_anomalous=0, seed=3)
    out = tmp_path / "models"
    saved = train_models("traffic", sample, out)
    assert saved["iforest"].name == "traffic_iforest.joblib"
    assert saved["autoencoder"].name == "traffic_autoencoder.joblib"
    assert saved["iforest"].exists() and saved["autoencoder"].exists()


def test_train_rejects_unknown_kind(tmp_path):
    with pytest.raises(ValueError):
        train_models("bogus", tmp_path / "x.csv", tmp_path / "out")


def test_models_require_fit_before_score():
    with pytest.raises(RuntimeError):
        IsolationForestModel().score(np.zeros((1, 5)))
    with pytest.raises(RuntimeError):
        AutoencoderModel().score(np.zeros((1, 5)))
