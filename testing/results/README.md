# Testing Results

This directory stores output from Person 3's evaluation runner.

## Generated Files

| File Pattern | Format | Contents |
|---|---|---|
| `evaluation_report_*.json` | JSON | Full structured report |
| `scenario_results_*.csv` | CSV | Per-scenario results table |
| `evaluation_summary_*.txt` | Text | Human-readable summary |
| `latest_report.json` | JSON | Most recent report (used by backend API) |

## How to Generate

```bash
python -m testing.run_evaluation
```

## Notes

- Results are timestamped; previous runs are preserved.
- `latest_report.json` is always overwritten with the most recent run.
- These files are git-ignored (generated artefacts).
