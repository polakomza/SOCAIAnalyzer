
from src.ingestion.column_mapper import suggest_mapping


def test_mapping_soc_excel():
    columns = [
        "Log_ID",
        "Timestamp",
        "Hostname",
        "Event_ID",
        "User",
        "Source_IP",
        "Destination",
        "Log_Source",
        "Event_Description",
        "Process_CommandLine",
        "Result",
        "Severity"
    ]

    mapping = suggest_mapping(columns)

    assert mapping["event_id"] == "Event_ID"
    assert mapping["process_commandline"] == (
        "Process_CommandLine"
    )
    assert mapping["event_description"] == (
        "Event_Description"
    )
    assert mapping["source"] == "Log_Source"
    assert mapping["destination"] == "Destination"
    assert mapping["username"] == "User"

    assert len(mapping.values()) == len(set(mapping.values()))
