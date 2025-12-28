"""Parallel traffic generation runners."""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor, as_completed

from ..config import Config
from ..logging_setup import get_logger
from ..state import GeneratorContext, set_default_context
from .tasks import build_tasks

logger = get_logger(__name__)


def _init_worker_context(config: Config) -> None:
    """Initialize per-worker generator context."""
    set_default_context(GeneratorContext(config, seed=config.seed))


def get_unique_output_dir(base_dir="temp_pcaps"):
    """
    Get unique output directory. If temp_pcaps exists, try temp_pcaps1, temp_pcaps2, etc.
    Returns: (directory_path, run_number)
    """
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
        return base_dir, 1

    counter = 1
    while True:
        new_dir = f"{base_dir}{counter}"
        if not os.path.exists(new_dir):
            os.makedirs(new_dir)
            return new_dir, counter
        counter += 1


def generate_all_traffic_fast(
    start_time,
    duration,
    output_dir="temp_pcaps",
    smb_size=100_000_000,
    smb_max_transfers=None,
    smb_enforce_short_run_caps=True,
    config: Config | None = None,
    workers: int | None = None,
):
    """
    Generate each traffic type directly to separate PCAP files.
    Uses multiprocessing for parallel execution.
    """
    config = config or Config.from_defaults()
    logger.info("\n[*] FAST MODE: Generating traffic streams in PARALLEL (multiprocessing)...")
    logger.info("[*] Each stream writes to its own PCAP file")
    worker_count = workers or os.cpu_count() or 4
    logger.info(f"[*] Using {worker_count} CPU cores")

    output_dir, run_number = get_unique_output_dir(output_dir)

    tasks = build_tasks(
        start_time,
        duration,
        output_dir,
        smb_size,
        smb_max_transfers,
        smb_enforce_short_run_caps,
        config,
    )

    logger.info("\n[*] Traffic Types:")
    for task in tasks:
        logger.info(f"    - {task.name:20s} - {task.description}")

    results = {}
    with ProcessPoolExecutor(
        max_workers=worker_count,
        initializer=_init_worker_context,
        initargs=(config,),
    ) as executor:
        future_to_name = {}
        for task in tasks:
            future = executor.submit(task.func, *task.args)
            future_to_name[future] = task.name

        completed = 0
        total_tasks = len(tasks)
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                packet_count, file_size = future.result()
                results[name] = (packet_count, file_size)
                completed += 1
                logger.info(f"[OK] {name:20s} complete: {packet_count:>7,d} packets, {file_size / (1024 * 1024):>6.1f} MB [{completed}/{total_tasks}]")
            except Exception as e:
                logger.info(f"[!] {name:20s} failed: {e}")
                import traceback

                traceback.print_exc()

    if len(results) < total_tasks:
        missing = total_tasks - len(results)
        logger.info(f"\n[!] WARNING: {missing} traffic types failed!")
        failed_types = set(t.name for t in tasks) - set(results.keys())
        logger.info(f"[!] Failed: {', '.join(failed_types)}")

    total_packets = sum(r[0] for r in results.values())
    total_size = sum(r[1] for r in results.values())

    logger.info("\n[OK] All traffic generated!")
    logger.info(f"    Total packets: {total_packets:,}")
    logger.info(f"    Total size: {total_size / (1024 * 1024):.1f} MB")
    logger.info(f"    Files in: {output_dir}/")
    logger.info(f"    Next step: mergecap -w final_corporate.pcap {output_dir}/*.pcap")

    return output_dir, results
