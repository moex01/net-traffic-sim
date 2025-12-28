"""Public API for estimating and generating PCAP traffic."""

from __future__ import annotations

from dataclasses import dataclass

from .config import Config
from .logging_setup import get_logger
from .orchestrator import (
    auto_configure_for_target_size,
    estimate_pcap_size_and_time,
    generate_all_traffic_fast,
    print_dry_run_plan,
)

logger = get_logger(__name__)


@dataclass(frozen=True)
class Estimate:
    config: Config
    smb_simulated_size: int
    smb_max_transfers: int | None
    smb_enforce_short_run_caps: bool
    estimated_size_mb: float
    estimated_time_minutes: float


@dataclass(frozen=True)
class GenerationResult:
    output_dir: str
    results: dict[str, tuple[int, int]]
    estimate: Estimate


def _resolve_smb_settings(
    *,
    config: Config,
    duration_minutes: int,
    target_size_mb: int,
    smoke: bool,
) -> tuple[int, int | None, bool]:
    """Compute SMB simulation sizing and caps for a run."""
    smb_simulated_size_mb = config.smb_simulated_size_mb
    smb_max_transfers = None
    smb_enforce_short_run_caps = True
    target_mb_per_hour = target_size_mb / max(duration_minutes / 60, 0.25)

    if smoke:
        smb_simulated_size_mb = min(smb_simulated_size_mb, 1)
        smb_max_transfers = 3
        logger.info("[*] Smoke mode: SMB transfers scaled down for quick validation.")
    else:
        if duration_minutes <= 15:
            smb_simulated_size_mb = min(smb_simulated_size_mb, 1)
            smb_max_transfers = 3
            logger.info("[*] Short run detected: scaling SMB transfers down.")
        elif duration_minutes <= 60:
            smb_simulated_size_mb = min(smb_simulated_size_mb, 3)
            smb_max_transfers = 5
            logger.info("[*] Short run detected: scaling SMB transfers down.")

        if duration_minutes <= 60 and target_mb_per_hour >= 150:
            smb_enforce_short_run_caps = False
            smb_max_transfers = 5
            if duration_minutes <= 15:
                smb_simulated_size_mb = max(smb_simulated_size_mb, 6)
            else:
                smb_simulated_size_mb = max(smb_simulated_size_mb, 12)
            logger.info("[*] High short-run target: keeping SMB transfers at 5 while increasing simulated size.")

    return smb_simulated_size_mb * 1024 * 1024, smb_max_transfers, smb_enforce_short_run_caps


def estimate(
    config: Config,
    *,
    start_time: float,
    duration_seconds: int,
    target_size_mb: int,
    allow_prompt: bool = False,
    smoke: bool = False,
) -> Estimate:
    """Estimate capture size and generation time."""
    adjusted_config = auto_configure_for_target_size(
        target_size_mb,
        duration_seconds,
        allow_prompt=allow_prompt,
        base_config=config,
    )
    duration_minutes = max(1, int(duration_seconds / 60))
    smb_simulated_size, smb_max_transfers, smb_enforce_short_run_caps = _resolve_smb_settings(
        config=adjusted_config,
        duration_minutes=duration_minutes,
        target_size_mb=target_size_mb,
        smoke=smoke,
    )
    estimated_size_mb, estimated_time_min = estimate_pcap_size_and_time(
        start_time,
        duration_seconds,
        target_size_mb,
        smb_simulated_size,
        smb_max_transfers=smb_max_transfers,
        config=adjusted_config,
    )
    return Estimate(
        config=adjusted_config,
        smb_simulated_size=smb_simulated_size,
        smb_max_transfers=smb_max_transfers,
        smb_enforce_short_run_caps=smb_enforce_short_run_caps,
        estimated_size_mb=estimated_size_mb,
        estimated_time_minutes=estimated_time_min,
    )


def generate(
    config: Config,
    *,
    start_time: float,
    duration_seconds: int,
    output_dir: str,
    target_size_mb: int,
    smoke: bool = False,
    dry_run: bool = False,
    allow_prompt: bool = False,
    estimate_result: Estimate | None = None,
    workers: int | None = None,
) -> GenerationResult | None:
    """Generate traffic PCAPs using the provided config."""
    estimation = estimate_result or estimate(
        config,
        start_time=start_time,
        duration_seconds=duration_seconds,
        target_size_mb=target_size_mb,
        allow_prompt=allow_prompt,
        smoke=smoke,
    )

    if dry_run:
        print_dry_run_plan(start_time, duration_seconds, target_size_mb, config=estimation.config)
        return None

    output_dir, results = generate_all_traffic_fast(
        start_time,
        duration_seconds,
        output_dir,
        estimation.smb_simulated_size,
        smb_max_transfers=estimation.smb_max_transfers,
        smb_enforce_short_run_caps=estimation.smb_enforce_short_run_caps,
        config=estimation.config,
        workers=workers,
    )

    return GenerationResult(output_dir=output_dir, results=results, estimate=estimation)
