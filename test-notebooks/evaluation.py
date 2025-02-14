import json
from rapidfuzz import fuzz
from collections import defaultdict

# Load STIX bundle manually
def load_stix_bundle(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# Extract SDOs, SCOs, and SROs from a STIX bundle
def extract_objects(bundle):
    sdos, scos, sros = defaultdict(list), defaultdict(list), []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship":
            sros.append(obj)
        elif obj.get("type") in [
            "attack-pattern", "campaign", "course-of-action", "identity", "indicator",
            "intrusion-set", "malware", "observed-data", "report", "threat-actor", "vulnerability", "infrastructure", "sighting", "note",
            "opinion", "grouping", "incident", "location", "malware-analysis"
        ]:
            sdos[obj["type"]].append(obj)
        elif obj.get("type") in [
            "artifact", "autonomous-system", "directory", "domain-name", "email-address",
            "email-message", "file", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex",
            "network-traffic", "process", "software", "url", "user-account",
            "windows-registry-key", "x509-certificate", "tool"
        ]:
            scos[obj["type"]].append(obj)
    return sdos, scos, sros

# Compute similarity between two SDOs
def compare_sdos(sdo1, sdo2):
    name_similarity = fuzz.ratio(sdo1.get("name", ""), sdo2.get("name", ""))
    desc_similarity = fuzz.ratio(sdo1.get("description", ""), sdo2.get("description", ""))
    avg_score = (name_similarity + desc_similarity) / 2
    return avg_score / 100  # Normalize to [0,1]

def compare_scos(sco1, sco2):
    #type_similarity = fuzz.ratio(sco1.get("type", ""), sco2.get("type", ""))
    print("comparing")
    print(sco1.get("name", ""))
    print(sco2.get("name", ""))
    name_similarity = fuzz.ratio(sco1.get("name", ""), sco2.get("name", ""))
    avg_score = name_similarity
    return avg_score / 100  # Normalize to [0,1]

def compare_sros(sro1, sro2, ground_truth_sdos, ground_truth_scos):
    if sro1["relationship_type"] != sro2["relationship_type"]:
        return 0
    
    source_type = sro2["source_ref"].split("--")[0]  # Extract object type
    target_type = sro2["target_ref"].split("--")[0]

    # Fetch the actual objects instead of passing IDs as strings
    source_similarity = any(compare_sdos(obj, gt_obj) > 0.7 for obj in ground_truth_sdos.get(source_type, []) for gt_obj in ground_truth_sdos.get(source_type, []))
    target_similarity = any(compare_sdos(obj, gt_obj) > 0.7 for obj in ground_truth_sdos.get(target_type, []) for gt_obj in ground_truth_sdos.get(target_type, []))

    return 1 if source_similarity and target_similarity else 0
# Calculate accuracy scores
def calculate_accuracy(output_objects, ground_truth_objects, comparison_fn):
    matches = 0
    total_score = 0
    total_output = sum(len(v) for v in output_objects.values())

    for obj_type, out_list in output_objects.items():
        print(obj_type)
        gt_list = ground_truth_objects.get(obj_type, [])
        print(gt_list)
        for out_obj in out_list:
            best_match = max((comparison_fn(out_obj, gt_obj) for gt_obj in gt_list), default=0)
            total_score += best_match
            matches += 1

    return total_score / total_output if total_output > 0 else 0

# Main function
def evaluate_model(output_file, ground_truth_file):
    output_bundle = load_stix_bundle(output_file)
    ground_truth_bundle = load_stix_bundle(ground_truth_file)

    output_sdos, output_scos, output_sros = extract_objects(output_bundle)
    ground_truth_sdos, ground_truth_scos, ground_truth_sros = extract_objects(ground_truth_bundle)

    sdo_score = calculate_accuracy(output_sdos, ground_truth_sdos, compare_sdos)
    print("here")
    

    print(f"SDO Accuracy: {sdo_score:.2f}")
    sco_score = calculate_accuracy(output_scos, ground_truth_scos, compare_scos)
    print(f"SCO Accuracy: {sco_score:.2f}")

# Run the evaluation
evaluate_model("APT1-gpt.json", "APT1.json")