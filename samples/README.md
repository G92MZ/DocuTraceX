# Samples

Benign sample files, one per in-scope type, for testing identification and the
parsers. **They are minimal and carry no findings yet** — findings-bearing
samples will be added later, on request.

Regenerate with:

```bash
python scripts/make_samples.py
```

## What each file is

| Family | Files | Nature |
|---|---|---|
| Word (OOXML) | `.docx` `.docm` `.dotx` `.dotm` | Minimal OPC/ZIP packages with the correct content type per extension |
| Excel (OOXML) | `.xlsx` `.xlsm` `.xltx` `.xltm` `.xlam` | Minimal OPC/ZIP packages |
| PowerPoint (OOXML) | `.pptx` `.pptm` `.potx` `.potm` `.ppsx` `.ppsm` `.ppam` `.sldx` `.sldm` | Minimal OPC/ZIP packages |
| Excel binary | `.xlsb` | OPC/ZIP package with a binary workbook part |
| Legacy Office | `.doc` `.dot` `.xls` `.xlt` `.xla` `.ppt` `.pot` | Minimal valid OLE/CFB compound files (container-valid, not full Office documents) |
| Email | `.eml` | Valid RFC 822 message |
| Email | `.emlx` | Apple Mail wrapper around an RFC 822 message |
| Email | `.msg` | Minimal valid OLE/CFB compound file (container-valid, not a full Outlook message) |
| PDF | `.pdf` | Minimal valid PDF |

## Notes

- The legacy OLE/CFB files (`.doc`, `.xls`, `.ppt`, `.msg`, ...) are valid
  compound-file *containers* but do not contain the Office/Outlook streams of a
  real document; they exercise the OLE/CFB branch and identification, not the
  semantic parsers yet.
- `libmagic` has no specific signature for `.emlx`, so it is identified as text;
  identification reports this as an *inconclusive* match (email is text-based),
  not a mismatch. The structural validator will confirm the EMLX wrapper later.
- These files are safe to upload to the app to see case creation, hashing and
  type identification (extension vs detected type) in action.
