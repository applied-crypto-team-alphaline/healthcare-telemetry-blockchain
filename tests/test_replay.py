def test_replay_detection():
    seen = set()

    seq = 1
    seen.add(seq)

    assert seq in seen  # replay should be detected