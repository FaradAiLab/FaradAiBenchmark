#!/usr/bin/env python3
"""
scripts/manage_cloud_models.py — CLI Cloud Provider & Model Registry Manager (ADR 0011).

Manages declarative cloud System One providers and models between DuckDB and YAML.
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from adapters.cloud_registry import (
    DEFAULT_DB_PATH,
    export_cloud_config,
    import_cloud_config,
    init_cloud_registry,
    list_cloud_models,
    list_cloud_providers,
)

console = Console()


def render_cloud_registry(db_path: Path) -> None:
    providers = list_cloud_providers(db_path)
    models = list_cloud_models(db_path)

    ptable = Table(title=f"Cloud Providers ({len(providers)})", header_style="bold cyan", show_lines=True)
    ptable.add_column("Provider ID", style="bold yellow")
    ptable.add_column("Dialect", style="magenta")
    ptable.add_column("Endpoint")
    ptable.add_column("API Key Env", style="green")
    ptable.add_column("Concurrency", justify="right")
    for p in providers:
        ptable.add_row(p.provider_id, p.dialect.value, f"{p.base_url}{p.endpoint_path}", p.api_key_env, str(p.max_concurrency))
    console.print(ptable)

    mtable = Table(title=f"Cloud Models ({len(models)})", header_style="bold cyan", show_lines=True)
    mtable.add_column("Model ID", style="bold yellow")
    mtable.add_column("Provider")
    mtable.add_column("Remote Slug", style="cyan")
    mtable.add_column("Profile")
    mtable.add_column("Price / 1M ($)", justify="right")
    mtable.add_column("Enabled", justify="center")
    for m in models:
        price_str = f"${m.input_price_per_1m_usd:.3f}" if m.input_price_per_1m_usd is not None else "N/A"
        mtable.add_row(
            m.model_id,
            m.provider_id,
            m.remote_model_slug,
            m.question_profile_id,
            price_str,
            "Yes" if m.enabled else "No",
        )
    console.print(mtable)


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage Cloud Decision Providers & Models in DuckDB")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="Path to DuckDB database")
    parser.add_argument("--import", dest="import_path", type=Path, help="Import providers/models from YAML")
    parser.add_argument("--export", dest="export_path", type=Path, help="Export providers/models to YAML")
    parser.add_argument("--list", action="store_true", help="List registered cloud providers and models")
    args = parser.parse_args()

    init_cloud_registry(args.db)

    if args.import_path:
        counts = import_cloud_config(args.import_path, args.db)
        console.print(
            f"[bold green]Imported {counts['providers']} provider(s) and {counts['models']} model(s) into {args.db}[/bold green]"
        )

    if args.export_path:
        export_cloud_config(args.export_path, args.db)
        console.print(f"[bold green]Exported cloud registry to {args.export_path}[/bold green]")

    if args.list or (not args.import_path and not args.export_path):
        render_cloud_registry(args.db)


if __name__ == "__main__":
    main()
