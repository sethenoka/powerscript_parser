# PowerScript Parser

PowerScript Parser is a Python 3 command line tool for forensically parsing PowerShell transcript files and PSReadLine `ConsoleHost_history.txt` files into structured output.

The default output is flat CSV with one record per command event.

## Supported Artifacts

- PowerShell transcripts named like `PowerShell_transcript.<computername>.<random>.<timestamp>.txt`
- PSReadLine history files named `ConsoleHost_history.txt`

PowerShell transcript parsing extracts session header metadata, command start times, raw command blocks, source line numbers, and decoded `-EncodedCommand` values when present. Console history parsing emits one event per nonblank history line and preserves the source file modified time separately rather than inventing per-command timestamps.

CSV output preserves embedded newlines inside quoted fields so long command blocks and decoded commands remain readable in tools that support multiline CSV fields. Multiline command fields are written with blank-line spacing between original lines for Timeline Explorer readability. Normalised event timestamps are rendered as `YYYY-MM-DD HH:MM:SS.ffff`.

## Usage

Run from source:

```bash
PYTHONPATH=src python3 -m powerscript_parser --help
```

Parse a recursive directory or zip collection:

```bash
PYTHONPATH=src python3 -m powerscript_parser -d ./triage_collection.zip -o ./out
```

Parse a single file:

```bash
PYTHONPATH=src python3 -m powerscript_parser -f ./ConsoleHost_history.txt --format json -o history.json
```

Parse only transcripts, only history, or both:

```bash
PYTHONPATH=src python3 -m powerscript_parser -d ./collection -a transcripts
PYTHONPATH=src python3 -m powerscript_parser -d ./collection -a history
PYTHONPATH=src python3 -m powerscript_parser -d ./collection -a all
```

Set the input timezone for transcript timestamps:

```bash
PYTHONPATH=src python3 -m powerscript_parser -d ./collection --input-timezone UTC
PYTHONPATH=src python3 -m powerscript_parser -d ./collection --input-timezone Australia/Perth
PYTHONPATH=src python3 -m powerscript_parser -d ./collection --input-timezone +08:00
```

## CLI Options

- `-d, --directory`: Recursive directory or `.zip` input. May be repeated.
- `-f, --file`: Single transcript or `ConsoleHost_history.txt` input. May be repeated.
- `-o, --output`: Output file or directory.
- `--format`: `csv`, `l2tcsv`, `json`, or `xml`. Default: `csv`.
- `-a, --artifact`: `transcripts`, `history`, or `all`. Default: `all`.
- `--input-timezone`: Timezone for transcript timestamps without offsets. Default: `UTC`.

## Defaults

If no `-d` or `-f` is supplied, the tool enumerates likely live-system locations:

- User profile transcript defaults under `Documents`
- PSReadLine history under `AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine`
- Centralised transcript roots such as `ProgramData/PowerShellTranscripts`

Microsoft documents the default `Start-Transcript` location and filename pattern as `$HOME\Documents` on Windows with filenames like `PowerShell_transcript.<computername>.<random>.<timestamp>.txt`: <https://learn.microsoft.com/powershell/module/microsoft.powershell.host/start-transcript>

If `-o` is omitted, output is written to the current directory as:

```text
powerscript_parser_<ISO_TIMESTAMP>.<ext>
```

Example:

```text
powerscript_parser_2026-05-03T073015Z.csv
```

If `-o` is an existing directory, the same default filename is written inside that directory. If `-o` has a file suffix, that exact file path is used.

## Output Formats

- `l2tcsv`: log2timeline-style CSV columns: `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`
- `csv`: flat parser-specific CSV fields, including `host_application`, process/version fields, line numbers, `is_impersonated`, one canonical decoded-command column set, and multiline command fields. The encoded payload is redacted from `host_application` when the same value is stored in `encoded_command`.
- `json`: array of event objects
- `xml`: one root element containing one `event` element per parsed record

For transcript events, `line_number` is the source line containing `Command start time:`. For history events, it's the original `ConsoleHost_history.txt` command line. `is_impersonated` is `true` when `user` and `run_as_user` are both populated and differ. Flat CSV intentionally omits the internal `metadata` object and the parser-normalised `command_text`; JSON/XML retain those full event details when needed.

## Development

Create a local virtual environment and run tests:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m unittest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy
```

The project is stdlib-only at runtime.

## License

PowerScript Parser is released under the MIT License.
