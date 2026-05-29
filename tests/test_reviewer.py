from src.reviewer.diff_parser import DiffParser

def test_diff_parser_extracts_additions() -> None:
    sample_diff = (
        "diff --git a/src/main.py b/src/main.py\n"
        "index 1234567..89abcde 100644\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "@@ -1,3 +1,4 @@\n"
        " def main():\n"
        "-    print('hello')\n"
        "+    # Security modification\n"
        "+    print('secure hello')\n"
        "     return 0\n"
    )
    
    files = DiffParser.parse_unified_diff(sample_diff)
    assert len(files) == 1
    assert files[0]["filename"] == "src/main.py"
    additions = files[0]["additions"]
    assert len(additions) == 2
    assert additions[0]["line_number"] == 2
    assert additions[0]["content"] == "    # Security modification"
    assert additions[1]["line_number"] == 3
    assert additions[1]["content"] == "    print('secure hello')"
