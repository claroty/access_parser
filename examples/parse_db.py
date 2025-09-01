from access_parser import AccessParser
from tabulate import tabulate
import json
import argparse


def print_tables(db_path, only_catalog=False, specific_table=None):
    db = AccessParser(db_path)
    if only_catalog:
        for k in db.catalog.keys():
            print(f"{k}\n")
    elif specific_table:
        table = db.parse_table(specific_table)
        print(f'TABLE NAME: {specific_table}\r\n')
        print(tabulate(table, headers="keys", disable_numparse=True))
        print("\n\n\n\n")
    else:
        db.print_database()

def dump_tables(db_path, specific_table=None):
    db = AccessParser(db_path)
    if specific_table:
        print(f'TABLE NAME: {specific_table}\r\n')
        table = db.get_table(specific_table)
        print(table.dump())
    else:
        for table_name in db.catalog.keys():
            print(f'TABLE NAME: {table_name}\r\n')
            table = db.get_table(table_name)
            dumped_table = table.dump()
            for row_number, row in enumerate(dumped_table):
                 print(f'{row_number}:\t {row}')
            print("\n\n\n\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dump", action="store_true", required=False, help="Dumps to a dictionary object", default=None)
    parser.add_argument("-c", "--catalog", required=False, help="Print DB table names", action="store_true")
    parser.add_argument("-f", "--file", required=True, help="*.mdb / *.accdb File")
    parser.add_argument("-t", "--table", required=False, help="Table to print", default=None)

    args = parser.parse_args()
    if args.dump:
        dump_tables(args.file)
    else:
        print_tables(args.file, args.catalog, args.table)
