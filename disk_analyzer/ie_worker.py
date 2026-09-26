"""Isolated, read-only libyal reader. This file also runs under Ubuntu's Python.

Its JSONL output is private evidence, not a public report. No third-party code
is imported into the main scanner process. See docs/architecture.md for sources.
"""
from __future__ import annotations

import importlib
import json
import resource
import sys

MODULES = {"ie-index": "pymsiecf", "ie-webcache": "pyesedb"}


def emit(value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


class Budget:
    def __init__(self, limit):
        self.limit = limit
        self.records = 0
        self.errors = 0
        self.limited = False

    def record(self, value):
        if self.records >= self.limit:
            self.limited = True
            return False
        emit(dict(value, event="record"))
        self.records += 1
        return True


def read_index(module, path, budget):
    database = module.file()
    database.open(path, "r")
    skipped = 0
    try:
        for recovered, total, getter in (
            (False, database.number_of_items, database.get_item),
            (True, database.number_of_recovered_items, database.get_recovered_item),
        ):
            for index in range(total):
                try:
                    item = getter(index)
                    if not isinstance(item, (module.url, module.redirected)):
                        skipped += 1
                        continue
                    redirected = isinstance(item, module.redirected)
                    record = {"table": "recovered" if recovered else "items", "record_id": index,
                              "offset": item.offset, "recovered": recovered, "location": item.location,
                              "item_type": "redirect" if redirected else item.type,
                              "primary_time": None if redirected else item.get_primary_time_as_integer(),
                              "secondary_time": None if redirected else item.get_secondary_time_as_integer(),
                              "access_count": None if redirected else item.number_of_hits}
                    if not budget.record(record):
                        return {"skipped_non_url_items": skipped}
                except (OSError, ValueError, OverflowError, UnicodeError):
                    budget.errors += 1
        return {"skipped_non_url_items": skipped, "format_version": database.format_version}
    finally:
        database.close()


def values(record, wanted):
    result = {}
    # Only decode the columns used by this parser, never arbitrary binary blobs.
    for index in range(record.number_of_values):
        name = record.get_column_name(index)
        if name not in wanted:
            continue
        if record.get_value_data(index) is None:
            result[name] = None
        elif wanted[name] == "text":
            result[name] = record.get_value_data_as_string(index)
        else:
            result[name] = record.get_value_data_as_integer(index)
    return result


def read_webcache(module, path, budget):
    database = module.file()
    database.open(path, "r")
    skipped = 0
    selected = 0
    try:
        containers = database.get_table_by_name("Containers")
        if containers is None:
            return {"not_browser": True}
        for index in range(containers.number_of_records):
            try:
                item = values(containers.get_record(index), {"ContainerId": "int", "Name": "text", "Directory": "text"})
                name, ident = item.get("Name"), item.get("ContainerId")
                if not isinstance(name, str) or not isinstance(ident, int):
                    budget.errors += 1
                    continue
                # Cache, cookie and download containers are not browsing visits.
                if name != "History" and not name.startswith("MSHist"):
                    skipped += 1
                    continue
                selected += 1
                table_name = f"Container_{ident}"
                table = database.get_table_by_name(table_name)
                if table is None:
                    budget.errors += 1
                    continue
                for record_index in range(table.number_of_records):
                    try:
                        fields = values(table.get_record(record_index), {
                            "EntryId": "int", "Url": "text", "AccessedTime": "int", "AccessCount": "int",
                            "CreationTime": "int", "ModifiedTime": "int"})
                        if not isinstance(fields.get("Url"), str) or not fields["Url"]:
                            budget.errors += 1
                            continue
                        if not budget.record({"table": table_name, "record_id": record_index,
                                              "container_id": ident, "container_name": name,
                                              "container_directory": item.get("Directory"),
                                              "entry_id": fields.get("EntryId"), "location": fields["Url"],
                                              "accessed_time": fields.get("AccessedTime"),
                                              "creation_time": fields.get("CreationTime"),
                                              "modified_time": fields.get("ModifiedTime"),
                                              "access_count": fields.get("AccessCount")}):
                            return {"history_containers": selected, "skipped_non_history_containers": skipped}
                    except (OSError, ValueError, OverflowError, UnicodeError):
                        budget.errors += 1
            except (OSError, ValueError, OverflowError, UnicodeError):
                budget.errors += 1
        return {"history_containers": selected, "skipped_non_history_containers": skipped}
    finally:
        database.close()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    family = argv[0]
    # Bound native parser memory independently of the main scanner.
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    try:
        module = importlib.import_module(MODULES[family])
    except ImportError:
        emit({"event": "unavailable", "module": MODULES[family]})
        return 3
    if len(argv) == 2 and argv[1] == "--probe":
        emit({"available": True, "module": MODULES[family], "version": module.get_version()})
        return 0
    budget = Budget(int(argv[2]))
    try:
        detail = (read_index if family == "ie-index" else read_webcache)(module, argv[1], budget)
    except (OSError, ValueError, OverflowError, UnicodeError, MemoryError) as exc:
        emit({"event": "failure", "type": type(exc).__name__})
        return 2
    emit(dict(detail, event="summary", records=budget.records, errors=budget.errors, limited=budget.limited,
              reader=MODULES[family], reader_version=module.get_version()))
    return 2 if budget.errors or budget.limited else 0


if __name__ == "__main__":
    sys.exit(main())
