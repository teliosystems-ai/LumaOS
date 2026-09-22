# Example input

`invoices.csv` is fictional test data for the first real Luma OS workflow. It is
safe to copy into a temporary folder, enroll that folder, and process the copy.

The deterministic importer requires these columns:

- `invoice_id`
- `vendor`
- `invoice_date` in `YYYY-MM-DD` form
- `category`
- `amount` as a decimal number
- `currency` as a three-letter code

All rows in one workflow must use the same currency. The example contains no
personal or confidential information.
