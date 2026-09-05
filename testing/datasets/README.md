# Testing Datasets

This directory is reserved for test datasets used by Person 3's
evaluation module.

## Notes

- Datasets are generated programmatically by the scenario modules
  in `testing/scenarios/`.
- No real network captures are stored here by default.
- To add a captured dataset, place it in CSV format following
  Person 1's schema:

  ```
  timestamp, sender_ip, sender_mac, target_ip, target_mac, operation
  ```

- All testing must be performed in an authorised, isolated lab
  environment only.
