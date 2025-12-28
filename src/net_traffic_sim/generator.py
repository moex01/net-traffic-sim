#!/usr/bin/env python3
"""
Corporate network PCAP generator entrypoint.
"""

import argparse
import sys
import time
from datetime import datetime
from importlib import metadata

from . import api
from .config import Config
from .logging_setup import configure_logging, get_logger
from .scapy_setup import configure_scapy


def main(argv=None):
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Corporate Network PCAP Generator - Realistic internal portal traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 500 MB PCAP for 12 hours
  net-traffic-sim --target-size 500 --duration 720
  
  # Generate 1 GB PCAP for 24 hours
  net-traffic-sim --target-size 1000 --duration 1440
  
  # Generate 250 MB PCAP for 6 hours (fast)
  net-traffic-sim --target-size 250 --duration 360
  
  # Estimate only (no generation)
  net-traffic-sim --target-size 500 --duration 720 --estimate-only
  
  # Custom output directory
  net-traffic-sim --target-size 1000 --duration 1440 --output-dir my_pcaps
  
  # Custom start time
  net-traffic-sim --target-size 500 --duration 720 --start-time "2025-10-30T08:00:00"
  
Duration reference (in minutes):
  60   = 1 hour
  360  = 6 hours
  720  = 12 hours
  1440 = 24 hours
  2880 = 48 hours
  
After generation, merge with:
  mergecap -w final.pcap temp_pcaps/*.pcap
        """,
    )

    # REQUIRED arguments
    parser.add_argument("--target-size", type=int, required=True, help="Target PCAP size in MB (REQUIRED)")
    parser.add_argument("--duration", type=int, required=True, help="Traffic duration in minutes (REQUIRED). Example: 720=12h, 1440=24h")

    # OPTIONAL arguments
    parser.add_argument("--output-dir", type=str, default="temp_pcaps", help="Output directory for PCAP files (default: temp_pcaps)")
    parser.add_argument("--start-time", type=str, default="now", help='Start timestamp ("now" or ISO 8601; naive times are local, use Z/offset for UTC)')
    parser.add_argument("--estimate-only", action="store_true", help="Show size and time estimates only (no generation)")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without generating PCAP")
    parser.add_argument("--smoke", action="store_true", help="Scale down SMB transfers for short validation runs")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--workers", type=int, default=None, help="Number of worker processes (default: CPU count)")
    prompt_group = parser.add_mutually_exclusive_group()
    prompt_group.add_argument("--prompt", action="store_true", help="Enable interactive confirmation prompts")
    prompt_group.add_argument("--no-prompt", action="store_true", help="Disable interactive prompts (default)")
    checksum_group = parser.add_mutually_exclusive_group()
    checksum_group.add_argument("--checksums", action="store_true", help="Enable checksum calculation (slower, more realistic)")
    checksum_group.add_argument("--no-checksums", action="store_true", help="Disable checksum calculation for speed (default)")

    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    logger = get_logger(__name__)

    # Validate target-size and duration
    if args.target_size < 1 or args.target_size > 100000:
        logger.error("Target size must be between 1 and 100,000 MB")
        return 1
    if args.duration < 1 or args.duration > 525600:
        logger.error("Duration must be between 1 and 525,600 minutes")
        return 1

    # Validate output directory path
    import os

    if args.output_dir:
        # Check if parent directory exists for relative paths
        output_path = os.path.abspath(args.output_dir)
        parent_dir = os.path.dirname(output_path)
        if parent_dir and not os.path.exists(parent_dir):
            logger.error(f"Parent directory does not exist: {parent_dir}")
            logger.error(f"Cannot create output directory: {args.output_dir}")
            return 1
        # Check if path is not a file
        if os.path.exists(output_path) and os.path.isfile(output_path):
            logger.error(f"Output path is a file, not a directory: {args.output_dir}")
            return 1

    configure_scapy(checksums=args.checksums)
    duration_minutes = args.duration
    duration_seconds = duration_minutes * 60

    def _parse_start_time(value: str) -> float:
        if value == "now":
            return datetime.now().timestamp()
        try:
            normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
            dt = datetime.fromisoformat(normalized)
            return dt.timestamp()
        except Exception as e:
            logger.error(f"[!] Error: Invalid start time format: {e}")
            logger.error("[!] Use 'now' or ISO format like '2025-10-29T08:00:00' or '2025-10-29T08:00:00Z'")
            raise

    # Calculate the capture start time from CLI arguments.
    try:
        start_time = _parse_start_time(args.start_time)
    except Exception:
        return 1

    # Print banner
    logger.info("=" * 70)
    logger.info("CORPORATE NETWORK PCAP GENERATOR - FAST MODE")
    logger.info("=" * 70)
    try:
        version = metadata.version("net-traffic-sim")
    except metadata.PackageNotFoundError:
        version = "unknown"
    logger.info(f"Version: {version} (Optimized for Speed)")
    logger.info("Target: Internal portal with SQL Server, Active Directory")
    logger.info("Mode: Parallel generation -> Separate PCAPs -> Manual merge")
    logger.info("=" * 70)
    logger.info("\nConfiguration:")
    logger.info(f"  Start time:   {datetime.fromtimestamp(start_time)}")
    logger.info(f"  Duration:     {duration_minutes} minutes ({duration_minutes / 60:.1f} hours)")
    logger.info(f"  Target size:  {args.target_size} MB")
    logger.info("=" * 70)

    allow_prompt = args.prompt and not args.estimate_only and not args.dry_run
    base_config = Config.from_defaults()
    estimation = api.estimate(
        base_config,
        start_time=start_time,
        duration_seconds=duration_seconds,
        target_size_mb=args.target_size,
        allow_prompt=allow_prompt,
        smoke=args.smoke,
    )
    estimated_time_min = estimation.estimated_time_minutes

    # Adjust time estimate for fast mode (no merge/sort overhead in Python)
    fast_mode_time = estimated_time_min * 0.25  # ~4x faster without merge/sort
    logger.info(f"\n[*] Fast Mode: Estimated time reduced to {fast_mode_time:.1f} minutes")
    logger.info(f"    (vs {estimated_time_min:.1f} minutes in standard mode)")

    # If estimate-only, stop here
    if args.estimate_only:
        logger.info("\n[*] Estimation complete. Use without --estimate-only to generate PCAP.")
        return 0

    # Dry run mode
    if args.dry_run:
        api.generate(
            base_config,
            start_time=start_time,
            duration_seconds=duration_seconds,
            output_dir=args.output_dir,
            target_size_mb=args.target_size,
            smoke=args.smoke,
            dry_run=True,
            allow_prompt=allow_prompt,
            estimate_result=estimation,
        )
        logger.info("\n[*] Dry-run mode. Estimation shown above. No PCAP will be generated.")
        return 0

    # Ask user to confirm if generation will take >10 minutes
    if fast_mode_time > 10:
        logger.warning(f"\n[!] WARNING: This will take approximately {fast_mode_time:.1f} minutes")
        if allow_prompt and sys.stdin.isatty():
            response = input("    Continue? [y/N]: ")
            if response.lower() not in ["y", "yes"]:
                logger.info("[*] Cancelled")
                return 0
        else:
            logger.warning("[!] Non-interactive mode: proceeding without confirmation.")
    else:
        logger.info(f"\n[OK] Ready to generate ({fast_mode_time:.1f} minutes). Press Ctrl+C to cancel...")
        if sys.stdin.isatty():
            try:
                time.sleep(3)
            except KeyboardInterrupt:
                logger.info("\n[*] Cancelled")
                return 0

    # Generate traffic (FAST MODE)
    try:
        generation_start = time.time()

        logger.info("\n[*] Starting FAST PCAP generation...")
        generation_result = api.generate(
            base_config,
            start_time=start_time,
            duration_seconds=duration_seconds,
            output_dir=args.output_dir,
            target_size_mb=args.target_size,
            smoke=args.smoke,
            dry_run=False,
            allow_prompt=allow_prompt,
            estimate_result=estimation,
            workers=args.workers,
        )
        if generation_result is None:
            logger.error("[!] Generation aborted unexpectedly.")
            return 1
        output_dir = generation_result.output_dir
        results = generation_result.results

        generation_end = time.time()
        elapsed = generation_end - generation_start

        # Calculate totals
        total_packets = sum(r[0] for r in results.values())
        total_bytes = sum(r[1] for r in results.values())

        # Show actual vs estimated time
        logger.info("\n" + "=" * 70)
        logger.info("GENERATION STATISTICS")
        logger.info("=" * 70)
        logger.info(f"Target size:              {args.target_size} MB")
        logger.info(f"Actual size:              {total_bytes / (1024 * 1024):.1f} MB")
        size_accuracy = (total_bytes / (1024 * 1024)) / args.target_size * 100
        logger.info(f"Size accuracy:            {size_accuracy:.0f}%")
        logger.info(f"\nTotal packets:            {total_packets:,}")
        logger.info(f"Files generated:          {len(results)}")
        logger.info(f"Output directory:         {output_dir}/")
        logger.info(f"\nActual generation time:   {elapsed / 60:.1f} minutes")
        logger.info(f"Estimated time:           {fast_mode_time:.1f} minutes")

        if elapsed / 60 > 0:
            time_accuracy = min(fast_mode_time / (elapsed / 60), (elapsed / 60) / fast_mode_time) * 100
            logger.info(f"Time estimation accuracy: {time_accuracy:.0f}%")

        logger.info("=" * 70)

        # Merge instructions
        logger.info("\n" + "=" * 70)
        logger.info("NEXT STEPS: MERGE PCAP FILES")
        logger.info("=" * 70)
        logger.info("\nTo create final sorted PCAP, run:")
        logger.info(f"  mergecap -w final_output.pcap {output_dir}/*.pcap")
        logger.info("\nThis will:")
        logger.info(f"  - Merge all {len(results)} PCAP files into one")
        logger.info("  - Sort packets by timestamp (chronological order)")
        logger.info("  - Take ~1-2 minutes")
        logger.info("\nAlternatively, for UNSORTED merge (faster, if order doesn't matter):")
        logger.info(f"  mergecap -a -w unsorted_output.pcap {output_dir}/*.pcap")
        logger.info("\nOr keep separate files for protocol-specific analysis:")
        logger.info(f"  {output_dir}/01_dns.pcap    - DNS traffic only")
        logger.info(f"  {output_dir}/02_sql.pcap    - SQL Server traffic only")
        logger.info(f"  {output_dir}/03_http.pcap   - HTTP portal traffic only")
        logger.info("  (etc.)")
        logger.info("=" * 70)

        return 0

    except KeyboardInterrupt:
        logger.warning("\n[!] Generation interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"\n[!] Fatal error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
