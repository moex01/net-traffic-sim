from __future__ import annotations

import pickle
from datetime import datetime
from pathlib import Path

from net_traffic_sim.api import generate
from net_traffic_sim.config import Config
from net_traffic_sim.state import GeneratorContext


def test_config_picklable():
    config = Config.from_defaults().with_overrides(sql_queries_per_sec=7, seed=123)
    data = pickle.dumps(config)
    loaded = pickle.loads(data)
    assert loaded == config


def test_generator_context_deterministic_seed():
    config = Config.from_defaults().with_overrides(seed=123)
    ctx1 = GeneratorContext(config, seed=123)
    ctx2 = GeneratorContext(config, seed=123)
    assert ctx1.random_pool.seq_num() == ctx2.random_pool.seq_num()
    assert ctx1.random_pool.ttl() == ctx2.random_pool.ttl()


def _read_magic(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(4)


def test_generate_smoke(tmp_path: Path):
    config = Config.from_defaults().with_overrides(seed=123)
    output_dir = tmp_path / "pcaps"
    start_time = datetime.now().replace(hour=12, minute=0, second=0, microsecond=0).timestamp()
    result = generate(
        config,
        start_time=start_time,
        duration_seconds=30,
        output_dir=str(output_dir),
        target_size_mb=5,
        smoke=True,
        allow_prompt=False,
    )
    assert result is not None
    pcap_files = sorted(output_dir.glob("*.pcap"))
    assert pcap_files, "expected at least one pcap file"
    sizes = [pcap.stat().st_size for pcap in pcap_files]
    assert max(sizes) >= 24
    magic = _read_magic(pcap_files[0])
    assert magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
