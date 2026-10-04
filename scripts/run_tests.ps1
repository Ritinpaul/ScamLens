# Run all ScamLens backend unit tests
$env:PYTHONPATH = "."
python -m pytest backend/tests -v
