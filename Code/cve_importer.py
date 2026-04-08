# Obtaining and processing CVE json **files**
# The code is to download nvdcve zip files from NIST since 2002 to the current year,
# unzip and append all the JSON files together,
# and extracts all the entries from json files of the projects.

import datetime
import json
import pandas as pd
from pathlib import Path
from extract_cwe_record import get_cwe_class,  extract_cwe
import configuration as cf
import database as db

#added
from collections import defaultdict
# ---------------------------------------------------------------------------------------------------------------------
INIT_YEAR = 2002
currentYear = datetime.datetime.now().year

ORDERED_CVE_COLUMNS = [
    'cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
    'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
    'user_interaction_required',
    'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
    'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
    'cvss2_base_score',
    'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
    'cvss3_privileges_required',
    'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
    'cvss3_integrity_impact',
    'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
    'exploitability_score', 'impact_score', 'ac_insuf_info',
    'reference_json', 'problemtype_json'
]

CWE_COLUMNS = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

def assign_cwes_to_cves(df_cve: pd.DataFrame):
    df_cwes = pd.read_sql('select * from cwe', db.conn)
    # fetching CWE associations to CVE records
    cf.logger.info('Adding CWE category to CVE records...')
    df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy()
    df_cwes_class['cwe_id'] = get_cwe_class(df_cwes_class['problemtype_json'].tolist())  # list of CWE-IDs' portion
    # exploding the multiple CWEs list of a CVE into multiple rows.
    df_cwes_class = df_cwes_class.assign(
        cwe_id=df_cwes_class.cwe_id).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')

    no_ref_cwes = set(list(df_cwes_class.cwe_id)).difference(set(list(df_cwes.cwe_id)))
    if len(no_ref_cwes) > 0:
        cf.logger.debug('List of CWEs from CVEs that are not associated to cwe table are as follows:')
        cf.logger.debug(no_ref_cwes)

    assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
        'Primary keys are not unique in cwe_classification records!'

    df_cwes_class.to_sql(name='cwe_classification', con=db.conn, if_exists='append', index=False)
    db.conn.commit()
    cf.logger.info('Added cwe and cwe_classification tables')

def get_english_description(descriptions):
    if not isinstance(descriptions, list):
        return pd.NA
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return item.get("value", pd.NA)
    return pd.NA


def extract_nodes(configurations): 
    if not isinstance(configurations, list):
        return pd.NA 
    all_nodes = [] 
    for cfg in configurations: 
        if isinstance(cfg, dict): 
            nodes = cfg.get("nodes") 
            if isinstance(nodes, list): 
                all_nodes.extend(nodes) 
    return all_nodes if all_nodes else pd.NA


def pick_preferred_metric(metric_list):
    """
    Prefer NVD source if present, otherwise return the first entry.
    """
    if not isinstance(metric_list, list) or not metric_list:
        return None

    for item in metric_list:
        if isinstance(item, dict) and item.get("source") == "nvd@nist.gov":
            return item

    return metric_list[0]


def extract_cve_row(data):
    metrics = data.get("metrics", {}) if isinstance(data, dict) else {}

    v2_item = pick_preferred_metric(metrics.get("cvssMetricV2", []))
    v31_item = pick_preferred_metric(metrics.get("cvssMetricV31", []))

    v2 = v2_item.get("cvssData", {}) if isinstance(v2_item, dict) else {}
    v31 = v31_item.get("cvssData", {}) if isinstance(v31_item, dict) else {}

    severity = (
        v31.get("baseSeverity")
        or (v31_item or {}).get("baseSeverity")
        or v2.get("baseSeverity")
        or (v2_item or {}).get("baseSeverity")
        or pd.NA
    )

    exploitability_score = (
        (v31_item or {}).get("exploitabilityScore")
        if v31_item is not None
        else (v2_item or {}).get("exploitabilityScore", pd.NA)
    )

    impact_score = (
        (v31_item or {}).get("impactScore")
        if v31_item is not None
        else (v2_item or {}).get("impactScore", pd.NA)
    )

    ac_insuf_info = (v2_item or {}).get("acInsufInfo", pd.NA)
    obtain_all_privilege = (v2_item or {}).get("obtainAllPrivilege", pd.NA)
    obtain_user_privilege = (v2_item or {}).get("obtainUserPrivilege", pd.NA)
    obtain_other_privilege = (v2_item or {}).get("obtainOtherPrivilege", pd.NA)
    user_interaction_required = (v2_item or {}).get("userInteractionRequired", pd.NA)

    if pd.isna(user_interaction_required):
        v31_ui = v31.get("userInteraction")
        if v31_ui is not None:
            user_interaction_required = (v31_ui != "NONE")

    row = {
        'cve_id': data.get("id", pd.NA),
        'published_date': data.get("published", pd.NA),
        'last_modified_date': data.get("lastModified", pd.NA),
        'description': get_english_description(data.get("descriptions")),
        'nodes': extract_nodes(data.get("configurations")),
        'severity': severity,

        'obtain_all_privilege': obtain_all_privilege,
        'obtain_user_privilege': obtain_user_privilege,
        'obtain_other_privilege': obtain_other_privilege,
        'user_interaction_required': user_interaction_required,

        'cvss2_vector_string': v2.get("vectorString", pd.NA),
        'cvss2_access_vector': v2.get("accessVector", pd.NA),
        'cvss2_access_complexity': v2.get("accessComplexity", pd.NA),
        'cvss2_authentication': v2.get("authentication", pd.NA),
        'cvss2_confidentiality_impact': v2.get("confidentialityImpact", pd.NA),
        'cvss2_integrity_impact': v2.get("integrityImpact", pd.NA),
        'cvss2_availability_impact': v2.get("availabilityImpact", pd.NA),
        'cvss2_base_score': v2.get("baseScore", pd.NA),

        'cvss3_vector_string': v31.get("vectorString", pd.NA),
        'cvss3_attack_vector': v31.get("attackVector", pd.NA),
        'cvss3_attack_complexity': v31.get("attackComplexity", pd.NA),
        'cvss3_privileges_required': v31.get("privilegesRequired", pd.NA),
        'cvss3_user_interaction': v31.get("userInteraction", pd.NA),
        'cvss3_scope': v31.get("scope", pd.NA),
        'cvss3_confidentiality_impact': v31.get("confidentialityImpact", pd.NA),
        'cvss3_integrity_impact': v31.get("integrityImpact", pd.NA),
        'cvss3_availability_impact': v31.get("availabilityImpact", pd.NA),
        'cvss3_base_score': v31.get("baseScore", pd.NA),
        'cvss3_base_severity': v31.get("baseSeverity", pd.NA),

        'exploitability_score': exploitability_score,
        'impact_score': impact_score,
        'ac_insuf_info': ac_insuf_info,

        'reference_json': data.get("references", pd.NA),
        'problemtype_json': data.get("weaknesses", pd.NA),
    }
    # print(data.get("id", pd.NA))
    # print(data.get("vulnStatus", pd.NA))
    # print(data.get("configurations", pd.NA)[0].get("nodes",pd.NA))
    # print()
    return row

def import_cves():
    """
    gathering CVE records by processing JSON files.
    """
    cf.logger.info('-' * 70)

    for tbl in ['cve', 'cwe', 'cwe_classification','fixes', 'cwe_classification', 'commits','file_change','method_change', 'repository']:
        if db.table_exists(tbl):
            db.execute_sql_cmd(f'DROP TABLE {tbl};')

    df_cwes = extract_cwe()
    # Applying the assertion to cve-, cwe- and cwe_classification table.
    assert df_cwes.cwe_id.is_unique, "Primary keys are not unique in cwe records!"

    df_cwes = df_cwes[CWE_COLUMNS].reset_index()  # to maintain the order of the columns
    df_cwes.to_sql(name="cwe", con=db.conn, if_exists='replace', index=False)
    db.conn.commit()

    github_cves_path =cf.GITHUB_CVE_PATH

    root = Path(github_cves_path)
    files_by_year = defaultdict(list)

    for path in root.iterdir():
        if not path.is_file():
            continue
        
        parts = path.stem.split("-")
        if len(parts) > 1 and parts[1].isdigit():
            year = int(parts[1])
            files_by_year[year].append(path)

    #kept yearly logic
    for year in range(INIT_YEAR, currentYear + 1):
        rows = []
        for path in files_by_year.get(year, []):
            with path.open("r", encoding="utf-8") as f:
                data = json.loads(f.read())
                #add only analyzed ones for quality
                #REMINDER de schimbat daca dataset-ul e prea mic
                if data.get("vulnStatus", pd.NA) == "Analyzed" and len(data.get("references")) > 0:
                    rows.append(extract_cve_row(data))
        cf.logger.info(f'Found {len(rows)} analyzed CVEs for {year} year')
        df = pd.DataFrame(rows)

        for col in ORDERED_CVE_COLUMNS:
            if col not in df.columns:
                df[col] = pd.NA
        
        df_cve = df[ORDERED_CVE_COLUMNS]

        for col in ["nodes", "reference_json", "problemtype_json"]:
            if col in df_cve.columns:
                df_cve[col] = df_cve[col].apply(
                    lambda x: json.dumps(x)
                    if isinstance(x, (dict, list))
                    else None
                )
        
        df_cve = df_cve.where(df_cve.notna(), None)
        df_cve = df_cve.replace({
            "None": None,
            "<NA>": None,
            "nan": None,
            "NaN": None
        })

        assert df_cve['cve_id'].is_unique, 'Primary keys are not unique in cve records!'

        df_cve.to_sql(name="cve", con=db.conn, if_exists="append", index=False)
        db.conn.commit()

    df_all_cves = pd.read_sql('select cve_id, problemtype_json from cve', db.conn)
    assign_cwes_to_cves(df_cve=df_all_cves)
