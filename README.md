# AccessDB Parser (Pure Python)
Microsoft Access (.mdb / .accdb) database files parser. The parsing logic is fully written in python and works without any external binary dependencies.

# Installing
Use pip: `pip install access-parser`

Requires Python 3.14 or newer. The package includes inline type information
for type checkers.

Or install from source with uv:
```bash
git clone https://github.com/ClarotyICS/access_parser.git
cd access_parser
uv sync
```

# Demo
[![asciicast](https://asciinema.org/a/345445.svg)](https://asciinema.org/a/345445)

# Usage Example
```python
from access_parser import AccessParser

# .mdb or .accdb file
db = AccessParser("/path/to/mdb/file.mdb")

# Print DB tables
print(db.catalog)

# Tables are stored as defaultdict(list) -- table[column][row_index]
table = db.parse_table("table_name")

# Access values use their corresponding Python types. In particular:
# Date/Time -> datetime.datetime, GUID -> uuid.UUID,
# Currency and Numeric/Decimal -> decimal.Decimal.

# Pretty print all tables
db.print_database()

```

## SQL Queries

Copy some or all parsed tables into a query-only, in-memory SQLite database:

```python
db = AccessParser("/path/to/mdb/file.mdb")
sql = db.to_sqlite(["Customers", "Orders"])

rows = sql.execute(
    """
    SELECT Customers.Name, SUM(Orders.Total)
    FROM Customers
    JOIN Orders ON Orders.CustomerID = Customers.ID
    GROUP BY Customers.Name
    """
).fetchall()

sql.close()
```

Omit the table list to import every table in `db.catalog`. The original Access
database is never modified; selected tables are fully parsed and copied into
memory before SQLite runs the query. Date/Time and GUID values are copied as
canonical text. Currency and Numeric/Decimal values are also copied as exact
text because SQLite has no arbitrary-precision decimal storage class; SQLite's
built-in numeric arithmetic may coerce those values to inexact floating point.

### Known Issues
* 

This library was tested on a limited subset of database files. Due to the differences between database versions and the complexity of the parsing we expect to find more parsing edge-cases.

To help us resolve issues faster please provide as much data as you can when opening an issue - DB file if possible and full trace including log messages.
 
 
### Thanks
* This library was made possible by the great work by mdb-tools. The logic in this library heavily relies on the excellent documentation they have https://github.com/brianb/mdbtools
* Huge thanks to Mashav Sapir for the help debugging, CRing and contributing to this project https://github.com/mashavs
