import json
from rapidfuzz import fuzz
from collections import defaultdict

def load_stix_bundle(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

SDO_TYPES = {
    "attack-pattern", "campaign", "course-of-action", "identity", "indicator",
    "intrusion-set", "malware", "observed-data", "report", "threat-actor", "vulnerability", 
    "infrastructure", "sighting", "note", "opinion", "grouping", 
    "incident", "location", "malware-analysis", "tool"
}

SCO_TYPES = {
    "artifact", "autonomous-system", "directory", "domain-name", "email-address", "email-message", "file",
    "ipv4-address", "ipv6-address", "mac-address", "mutex", "network-traffic", "process", "software",
    "url", "user-account", "windows-registry-key", "x-509-certificate", "http-request", "icmp", "socket-ext",
    "tcp-ext", "archive-ext", "raster-image-ext", "ntfs-ext", "pdf-ext", "unix-account-ext", "windows-pe-binary-ext",
    "windows-process-ext", "windows-service-ext", "windows-registry-ext", "jpeg-file-ext", "email-mime-component",
    "email-mime-multipart-type", "email-mime-message-type", "email-mime-text-type"
}

def extract_output(stix_bundle):
    """Extracts all STIX Domain Objects (SDOs) from a STIX bundle."""
    objects = stix_bundle.get("objects", [])
    sdos = [obj for obj in objects if obj.get("type") in SDO_TYPES]
    scos = [obj for obj in objects if obj.get("type") in SCO_TYPES]
    sros = [obj for obj in objects if obj.get("type") == "relationship"]
    return sdos, scos, sros

def extract_ground_truth(stix_bundle):
    """Extracts all STIX Domain Objects (SDOs) from a STIX bundle."""
    objects = stix_bundle.get("objects", [])
    sdcos = [obj for obj in objects if obj.get("type") in SDO_TYPES | SCO_TYPES]
    sros = [obj for obj in objects if obj.get("type") == "relationship"]
    return sdcos, sros

def compare_sdos(sdo1, sdo2):
    name_similarity = fuzz.ratio(sdo1.get("name", ""), sdo2.get("name", ""))
    desc_similarity = fuzz.ratio(sdo1.get("description", ""), sdo2.get("description", ""))
    avg_score = (name_similarity + desc_similarity) / 2

    print(sdo1.get("name", ""))
    print(sdo2.get("name", ""))
    print(name_similarity)

    print(sdo1.get("description", ""))
    print(sdo2.get("description", ""))
    print(desc_similarity)
    return avg_score / 100  

def compare_scos(sco1, sco2):
    type_similarity = fuzz.ratio(sco1.get("type", ""), sco2.get("type", ""))
    name_similarity = fuzz.ratio(sco1.get("name", ""), sco2.get("name", ""))
    avg_score = (type_similarity + name_similarity) / 2
    return avg_score / 100  

def compare_sros(sro1, sro2):
    type_similarity = fuzz.ratio(sro1.get("relationship_type", ""), sro2.get("relationship_type", ""))
    source_ref1 = sro1.get("source_ref", "").split("--")[0]
    source_ref2 = sro2.get("source_ref", "").split("--")[0]
    target_ref1 = sro1.get("target_ref", "").split("--")[0]
    target_ref2 = sro2.get("target_ref", "").split("--")[0]
    source_similarity = fuzz.ratio(source_ref1, source_ref2)
    target_similarity = fuzz.ratio(target_ref1, target_ref2)
    avg_score = (type_similarity + source_similarity + target_similarity) / 3
    return avg_score  / 100

def calculate_accuracy(output_obj, ground_truth, comparison_fn):
    total = 0
    for obj in output_obj:
        best_match = max((comparison_fn(obj, gt) for gt in ground_truth), default=0)
        total += best_match
    return total / len(output_obj)

def calculate_sdo_score(bundle_sdo, ground_truth):
    total = 0
    for sdo in bundle_sdo:
        for gt in ground_truth:
            name_similarity = fuzz.ratio(sdo.get("name", ""), gt.get("name", ""))
            if  name_similarity > 80:
                type_similarity = fuzz.ratio(sdo.get("type", ""), gt.get("type", ""))
                desc_similarity = fuzz.ratio(sdo.get("description", ""), gt.get("description", ""))
                score = (name_similarity + type_similarity + desc_similarity) / 3
                print(sdo.get("name", ""), gt.get("name", ""), name_similarity, type_similarity, desc_similarity, score)
                total += score
                break
    normalized_score = (total / len(bundle_sdo)) / 100
    return normalized_score

def calculate_sco_score(bundle_sco, ground_truth):
    print(bundle_sco)
    total = 0
    for sco in bundle_sco:
        for gt in ground_truth:
            name_similarity = fuzz.ratio(sco.get("name", ""), gt.get("name", ""))
            if  name_similarity > 80:
                type_similarity = fuzz.ratio(sco.get("type", ""), gt.get("type", ""))
                score = (name_similarity + type_similarity) / 2
                print(sco.get("name", ""), gt.get("name", ""), name_similarity, type_similarity, score)
                total += score
                break
    normalized_score = (total / len(bundle_sco)) / 100
    return normalized_score

def evaluate_model(output_file, ground_truth_file):
    output_bundle = load_stix_bundle(output_file)
    ground_truth_bundle = load_stix_bundle(ground_truth_file)

    output_sdos, output_scos, output_sros = extract_output(output_bundle)
    ground_truth, ground_truth_sros = extract_ground_truth(ground_truth_bundle)

    sdo_score = calculate_sdo_score(output_sdos, ground_truth)
    #sco_score = calculate_sco_score(output_scos, ground_truth)
    #sro_score = calculate_accuracy(output_sros, ground_truth_sros, compare_sros)
    #accuracy = (sdo_score + sco_score + sro_score) / 3
    
    print(f"SDO Score: {sdo_score:.2f}")
    #print(f"SCO Score: {sco_score:.2f}")
    #print(f"SRO Score: {sro_score:.2f}")
    #print(f"Total Accuracy: {accuracy:.2f}")
 

# Run the evaluation
evaluate_model("bundle_APT1_update.json", "APT1.json")