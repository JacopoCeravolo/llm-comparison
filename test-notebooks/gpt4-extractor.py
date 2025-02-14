import openai 
import stix2
import json

def query_model(messages):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=messages
    )
    return response.choices[0].message.content

# Add UUIDs to 'id' fields in STIX objects, ensuring each object has a unique identifier.
def add_uuid_to_ids(stix_data):
    """
    Add UUIDs to 'id' fields in STIX objects.
    """
    for item in stix_data:
        if 'id' in item:
            object_type = item['type']
            item['id'] = f"{object_type}--{uuid.uuid4()}"
    return stix_data

#Validate a list of STIX objects against the STIX 2.1 standard, identifying any invalid objects.
def validate_stix_objects(stix_objects):
    """
    Validate STIX objects against the STIX 2.1 standard.
    """
    all_valid = True
    invalid_objects = []
    for obj in stix_objects:
        try:
            # Parse the object to validate against the STIX 2.1 standard
            stix_obj = parse(json.dumps(obj), allow_custom=True)
            print(f"Validation passed for object ID: {obj.get('id')}")
        except exceptions.STIXError as se:
            print(f"STIX parsing error for object ID {obj.get('id')}: {se}")
            invalid_objects.append(obj)
            all_valid = False
        except json.JSONDecodeError as je:
            print(f"JSON parsing error: {je}")
            invalid_objects.append(obj)
            all_valid = False
    return all_valid, invalid_objects

client = openai.OpenAI(
    api_key=''
    )

text = r"""APT19 is a Chinese-based threat group that has targeted a variety of industries, including defense, finance, energy, pharmaceutical, telecommunications, high tech, education, manufacturing, and legal services. In 2017, a phishing campaign was used to target seven law and investment firms. Some analysts track APT19 and Deep Panda as the same group, but it is unclear from open source information if the groups are the same. APT19 used HTTP for C2 communications. APT19 also used an HTTP malware variant to communicate over HTTP for C2. An APT19 HTTP malware variant establishes persistence by setting the Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Windows Debug Tools-%LOCALAPPDATA%\. APT19 downloaded and launched code within a SCT file. APT19 used PowerShell commands to execute payloads. An APT19 Port 22 malware variant registers itself as a service. An APT19 HTTP malware variant used Base64 to encode communications to the C2 server. An APT19 HTTP malware variant decrypts strings using single-byte XOR keys. APT19 performed a watering hole attack on forbes.com in 2014 to compromise targets. APT19 used -W Hidden to conceal PowerShell windows by setting the WindowStyle parameter to hidden. APT19 launched an HTTP malware variant and a Port 22 malware variant using a legitimate executable that loaded the malicious DLL. APT19 uses a Port 22 malware variant to modify several Registry keys. APT19 used Base64 to obfuscate commands and the payload. APT19 has obtained and used publicly-available tools like Empire. APT19 sent spearphishing emails with malicious attachments in RTF and XLSM formats to deliver initial exploits. APT19 used Regsvr32 to bypass application control techniques. APT19 configured its payload to inject into the rundll32.exe. APT19 collected system architecture information. APT19 used an HTTP malware variant and a Port 22 malware variant to gather the hostname and CPU information from the victim’s machine. APT19 used an HTTP malware variant and a Port 22 malware variant to collect the MAC address and IP address from the victim’s machine. APT19 used an HTTP malware variant and a Port 22 malware variant to collect the victim’s username. APT19 attempted to get users to launch malicious attachments delivered via spearphishing emails."""
user_prompt = f"Text: {text}"


sdo_prompt = (
    # Role
    "You are a high skilled CTI analyst who focuses on STIX Domain Objects (SDOs), with a strong drive for accuracy and validity."
    # Task 
    "You are tasked with creating STIX 2.1 Domain Objects (SDOs) from the provided threat intelligence text" # add step-by-step process
    ""
    # Specifics
    "Possible SDOs include: Attack Pattern, Campaign, Course of Action, Identity, Indicator, Intrusion Set, Malware, Observed Data, Report, Threat Actor, Tool, Vulnerability, Infrastructure, Relationship, Sighting, Note, Opinion, Grouping, Incident, Location, Malware Analysis."
    "Create relevant SDOs in JSON format, strictly adhering to the STIX 2.1 specification."
    "The is_family field indicates whether the malware is a family (if true) or an instance (if false). The values true or false are always enclosed in quotes."
    "Don't use created_by_ref and source_ref"
    "The labels property in malware is used to categorize or tag the malware object with descriptive terms (e.g., \"trojan\", \"backdoor\", \"ransomware\"), Must contain at least one string."
    "threat-actor labels property should be an array of strings representing categories or descriptive terms for the threat actor."
    # Context
    "The goal is to extract a STIX 2.1 bundle from the text provided, your role is to extract the SDOs found in the text which will be bundled with the relationships and observable found by others."
    "By accurately extracting the SDOs, you contribute importantly to the creation of the bundle, so keep in mind to be very accurate and reliable."
    # Example
    "This is an example of an SDOs:"
    """[
    {
        "type": "threat-actor",
        "id": "threat-actor--a63b9ab7-7253-432d-98ea-5381207c74af",
        "name": "APT42",
        "description": "APT42 is an Iranian state-sponsored cyber espionage actor targeting Western and Middle Eastern NGOs, media organizations, academia, legal services, and activists. It operates on behalf of the Islamic Revolutionary Guard Corps Intelligence Organization (IRGC-IO).",
        "labels": [
            "state-sponsored",
            "cyber-espionage",
            "Iranian"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "intrusion-set",
        "id": "intrusion-set--7e9242ea-dcab-49cf-8e6b-22919d2b361c",
        "name": "APT42 Operations",
        "description": "APT42 uses enhanced social engineering schemes to gain access to victim networks, including cloud environments, by harvesting credentials and using them to gain initial access. It exfiltrates data of strategic interest to Iran, using built-in features and open-source tools to avoid detection.",
        "labels": [
            "intrusion-set",
            "APT42"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "malware",
        "id": "malware--d10904bd-10b9-4045-b514-f6c5f7d1de50",
        "name": "NICECURL",
        "description": "NICECURL is a backdoor written in VBScript that can download additional modules to be executed, including data mining and arbitrary command execution.",
        "is_family": "true",
        "labels": [
            "backdoor",
            "VBScript"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "malware",
        "id": "malware--00c9240a-4365-4101-8be4-66a0bc8f0530",
        "name": "TAMECAT",
        "description": "TAMECAT is a PowerShell toehold that can execute arbitrary PowerShell or C# content. It is used by APT42 to gain initial access to targets.",
        "is_family": "true",
        "labels": [
            "PowerShell",
            "backdoor"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "campaign",
        "id": "campaign--d00537dc-68aa-494b-b8fc-3e0ebf3204ce",
        "name": "APT42 Credential Harvesting Operations",
        "description": "APT42 conducts extensive credential harvesting operations through spear-phishing campaigns and social engineering, targeting individuals and organizations in policy, government, media, and NGOs.",
        "labels": [
            "credential-harvesting",
            "spear-phishing"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    }
    ]"""
    # Notes
    "Ensure the output is a valid JSON array ([...]) containing only SDOs identified with high confidence."
    "For id property write just SDO_type-- following this example: \"id\": \"malware--\""
    "Timestamp must be in ISO 8601 format."
    "Return only the JSON array, without any additional text, commentary, or code block delimiters (e.g., json)."
)

sdo_prompt = (
    # Role
    "You are a high skilled CTI analyst who focuses on STIX Cyber-Observable Objects (SCOs), with a strong drive for accuracy and validity."
    # Task 
    "You are tasked with creating STIX 2.1 Cyber-Observable Objects (SCOs) from the provided threat intelligence text" # add step-by-step process
    ""
    # Specifics
    "Possible SCOs include: Attack Pattern, Campaign, Course of Action, Identity, Indicator, Intrusion Set, Malware, Observed Data, Report, Threat Actor, Tool, Vulnerability, Infrastructure, Relationship, Sighting, Note, Opinion, Grouping, Incident, Location, Malware Analysis."
    "Create relevant SCOs in JSON format, strictly adhering to the STIX 2.1 specification."
    "The is_family field indicates whether the malware is a family (if true) or an instance (if false). The values true or false are always enclosed in quotes."
    "Don't use created_by_ref and source_ref"
    "The labels property in malware is used to categorize or tag the malware object with descriptive terms (e.g., \"trojan\", \"backdoor\", \"ransomware\"), Must contain at least one string."
    "threat-actor labels property should be an array of strings representing categories or descriptive terms for the threat actor."
    # Context
    "The goal is to extract a STIX 2.1 bundle from the text provided, your role is to extract the SDOs found in the text which will be bundled with the relationships and observable found by others."
    "By accurately extracting the SDOs, you contribute importantly to the creation of the bundle, so keep in mind to be very accurate and reliable."
    # Example
    "This is an example of an SDOs:"
    """[
    {
        "type": "threat-actor",
        "id": "threat-actor--a63b9ab7-7253-432d-98ea-5381207c74af",
        "name": "APT42",
        "description": "APT42 is an Iranian state-sponsored cyber espionage actor targeting Western and Middle Eastern NGOs, media organizations, academia, legal services, and activists. It operates on behalf of the Islamic Revolutionary Guard Corps Intelligence Organization (IRGC-IO).",
        "labels": [
            "state-sponsored",
            "cyber-espionage",
            "Iranian"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "intrusion-set",
        "id": "intrusion-set--7e9242ea-dcab-49cf-8e6b-22919d2b361c",
        "name": "APT42 Operations",
        "description": "APT42 uses enhanced social engineering schemes to gain access to victim networks, including cloud environments, by harvesting credentials and using them to gain initial access. It exfiltrates data of strategic interest to Iran, using built-in features and open-source tools to avoid detection.",
        "labels": [
            "intrusion-set",
            "APT42"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "malware",
        "id": "malware--d10904bd-10b9-4045-b514-f6c5f7d1de50",
        "name": "NICECURL",
        "description": "NICECURL is a backdoor written in VBScript that can download additional modules to be executed, including data mining and arbitrary command execution.",
        "is_family": "true",
        "labels": [
            "backdoor",
            "VBScript"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "malware",
        "id": "malware--00c9240a-4365-4101-8be4-66a0bc8f0530",
        "name": "TAMECAT",
        "description": "TAMECAT is a PowerShell toehold that can execute arbitrary PowerShell or C# content. It is used by APT42 to gain initial access to targets.",
        "is_family": "true",
        "labels": [
            "PowerShell",
            "backdoor"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    },
    {
        "type": "campaign",
        "id": "campaign--d00537dc-68aa-494b-b8fc-3e0ebf3204ce",
        "name": "APT42 Credential Harvesting Operations",
        "description": "APT42 conducts extensive credential harvesting operations through spear-phishing campaigns and social engineering, targeting individuals and organizations in policy, government, media, and NGOs.",
        "labels": [
            "credential-harvesting",
            "spear-phishing"
        ],
        "created": "2024-05-01T00:00:00Z",
        "modified": "2024-05-01T00:00:00Z"
    }
    ]"""
    # Notes
    "Ensure the output is a valid JSON array ([...]) containing only SDOs identified with high confidence."
    "For id property write just SDO_type-- following this example: \"id\": \"malware--\""
    "Timestamp must be in ISO 8601 format."
    "Return only the JSON array, without any additional text, commentary, or code block delimiters (e.g., json)."
)


sro_prompt = (

)

messages = [
    {"role": "system", "content": sdo_prompt},
    {"role": "user", "content": user_prompt}
]

print("Querying model...")
extracted_sdo = query_model(messages)

print(extracted_sdo)