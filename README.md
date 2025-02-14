# Comparing LLMs on STIX 2.1 extraction from pdf reports

Thesis for Technical University of Berlin

### Folders

- `bundles`: contains the extracted bundles and the ground truths.
- `notebooks`: contains the experiment notebooks, in particular:
  - `update_extractor.py`: extracts SDOs from a different block of texts by updating the list of SDOs found in the previous blocks.
  - `merge_extractor.py`: extracts SDOs from a different block of texts by creating separate lists of SDOs for each block, then merges them with gpt-4.
  - `evaluate_sdo.py`: compare the extracted SDOs of the output bundle against the ground truth `bundles/APT1_ground-truth.json`.
- `pdf-report`: original reports.
- `stixnet-data`: summarised text reports from STIXnet paper.
- `test-notebooks`: some testing but unused notebooks and scripts.

## Methodology

1. The text is extracted from the pdf report and store into blocks of fixed sized (due to gpt-4 token limit).
2. The extractor than starts a loop over the text blocks and queries the model for the STIX 2.1 Domain Objects.
   - In the `update_extractor.py`, the SDOs are extracted by updating the list of SDOs found in the previous blocks and passing that to the model with the prompt.
   - In the `merge_extractor.py`, the SDOs are extracted by creating separate lists of SDOs for each block, then merging them with another model request.
3. The SDOs are compared by iterating over each object in the output bundle:
   - For each object, we check if an object with a similar name is found in the ground truth
   - If the object is present in the ground truth, similarity score are calculated for the object name, type and description.
   - Similarity scores are calculated using `rapidfuzz` `ratio` function.
   - The similarity scores are then summed up and normalised.
