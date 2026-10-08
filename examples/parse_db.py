"""Print tables from an Access database."""

import argparse
import os

from tabulate import tabulate

from access_parser import AccessParser


def print_tables(
    db_path: str | os.PathLike[str],
    only_catalog: bool = False,
    specific_table: str | None = None,
) -> None:
    """Print the catalog, one table, or the complete database."""
    db = AccessParser(db_path)
    if only_catalog:
        for k in db.catalog:
            print(f"{k}\n")
    elif specific_table:
        table = db.parse_table(specific_table)
        print(f"TABLE NAME: {specific_table}\r\n")
        print(tabulate(table, headers="keys", disable_numparse=True))
        print("\n\n\n\n")
    else:
        db.print_database()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--catalog", required=False, help="Print DB table names", action="store_true")
    parser.add_argument("-f", "--file", required=True, help="*.mdb / *.accdb File")
    parser.add_argument("-t", "--table", required=False, help="Table to print", default=None)

    args = parser.parse_args()
    print_tables(args.file, args.catalog, args.table)
