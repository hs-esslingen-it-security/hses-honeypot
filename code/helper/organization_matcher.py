import logging
import ipaddress
from enum import Enum
import pandas as pd
import numpy as np
from pathlib import Path

rapid7_ip_ranges = [
    "5.63.151.96/27",
    "71.6.233.0/24",
    "88.202.190.128/27",
    "146.185.25.160/27",
    "109.123.117.224/27",
]
rapid7_ip_nets = [ipaddress.IPv4Network(prefix) for prefix in rapid7_ip_ranges]

def check_rapid7_ips(ip: str) -> bool:
    check_ip = ipaddress.IPv4Address(ip)

    for net in rapid7_ip_nets:
        if check_ip in net:
            return True
    return False

def find_potentially_orgas(df):
    """ Hostnames that contain scan """
    hostname_scan_df = df[df["hostname"].str.contains("scan")].groupby(["hostname"]).size().reset_index(name='size').sort_values(by = 'hostname')
    print(hostname_scan_df.to_string())

    """ Hostnames that contain probe """
    hostname_probe_df = df[df["hostname"].str.contains("probe")].groupby(["hostname"]).size().reset_index(name='size').sort_values(by = 'hostname')
    print(hostname_probe_df.to_string())

    """ Hostnames that contain measurement """
    hostname_measurement_df = df[df["hostname"].str.contains("measurement")].groupby(["hostname"]).size().reset_index(name='size').sort_values(by = 'hostname')
    print(hostname_measurement_df.to_string())

    """ Hostnames that contain research """
    hostname_research_df = df[df["hostname"].str.contains("research")].groupby(["hostname"]).size().reset_index(name='size').sort_values(by = 'hostname')
    print(hostname_research_df.to_string())

    """ Hostnames that contain security """
    hostname_security_df = df[df["hostname"].str.contains("security")].groupby(["hostname"]).size().reset_index(name='size').sort_values(by = 'hostname')
    print(hostname_security_df.to_string())

    """ Company names with security"""
    company_names_with_sec = df[df["company.name"].str.contains("security")].groupby(["company.name", "hostname", "SRC"]).size().reset_index(name='size').sort_values(by = 'company.name')
    print(company_names_with_sec.to_string())

    """ ASN that contains university """
    asn_university = df[df["asn.name"].str.lower().str.contains("university")].groupby("asn.name").size().reset_index(name='size').sort_values(by = 'asn.name')
    print(asn_university.to_string())

    """ ASN that contains education """
    edu_university = df[df["asn.name"].str.lower().str.contains("education")].groupby("asn.name").size().reset_index(name='size').sort_values(by = 'asn.name')
    print(edu_university.to_string())

    """ Hostnames that contain university """
    hostname_university = df[df["hostname"].str.contains("university")].groupby("hostname").size().reset_index(name='size').sort_values(by = 'hostname')
    print(hostname_university.to_string())

    """ Hostnames that contain education """
    hostname_edu = df[df["hostname"].str.contains("education")].groupby("hostname").size().reset_index(name='size').sort_values(by = 'hostname')
    print(hostname_edu.to_string())

    """ Company name with university """
    company_university_df = df[df["company.name"].str.lower().str.contains("university")].groupby(["company.name"]).size().reset_index(name='size').sort_values(by = 'company.name')
    print(company_university_df.to_string())

    """ use ipinfo type field for EDU """
    edu_df = df[df["asn.type"] == "education"]
    edu_host = edu_df.groupby("hostname").size().size().reset_index(name='size').sort_values(by = 'hostname')
    print(edu_host.to_string())
    

class OrganizationType(Enum):
    ORGANIZATION = 0
    HOSTING_ORGANIZATION = 1


def identify_organization(
    df: pd.DataFrame,
    query: pd.Series,
    organization_name: str,
    organization_short: str,
    organization_label: str,
    orga_type: OrganizationType = OrganizationType.ORGANIZATION
) -> None:
    """Writes the organization name to all rows in the DataFrame that match the given query"""

    # Negating the query makes it more natural (the query parameter expects all rows to be True
    # that match the organization)
    negated_query = ~query

    col = ''

    absolute_matches = query.sum()
    relative_matches = query.sum() / df.shape[0] * 100
    if orga_type == OrganizationType.ORGANIZATION:
        col = 'organization'
        logging.info(
            f'Packets that match the organization {organization_name}: '
            f'{absolute_matches} ({relative_matches:.2f} %)'
        )
    elif orga_type == OrganizationType.HOSTING_ORGANIZATION:
        col = 'hosting_organization'
        logging.info(
            f'Packets that match the hosting organization {organization_name}: '
            f'{absolute_matches} ({relative_matches:.2f} %)'
        )
    else:
        raise Exception('Invalid organization')

    df[col].where(
        negated_query,
        organization_name,
        inplace=True
    )
    if orga_type == OrganizationType.ORGANIZATION:
        df['organization_short'].where(
            negated_query,
            organization_short,
            inplace=True
        )
        df['organization_label'].where(
            negated_query,
            organization_label,
            inplace=True
        )
    


def identify_organizations(one_df: pd.DataFrame):
    one_df["organization"] = None
    one_df["organization_short"] = None
    one_df["organization_label"] = None
    one_df["hosting_organization"] = None
    

    ######## ORGANIZATIONS ########
    
    """ Censys """
    identify_organization(
        one_df,
        (one_df["company.name"].str.contains("Censys")) |
        (one_df["asn.name"].str.contains("Censys")),
        "Censys",
        "Censys",
        "Commercial"
    )

    """ internet-measurement.com aka driftnet.io """
    identify_organization(
        one_df,
        (one_df["asn.name"].str.contains("INTERNET MEASUREMENT")) |
        (one_df["hostname"].str.contains("internet-measurement.com")),
        "driftnet.io",
        "driftnet.io",
        "Commercial"
    )

    """ Recyber Project """
    identify_organization(
        one_df,
        (one_df["company.name"].str.contains("RECYBER PROJECT NETBLOCK")) |
        (one_df["company.domain"].str.contains("recyber.net")),
        "Recyber Project",
        "Recyber Project",
        "Research"
    )

    """ Palo Alto Networks """
    identify_organization(
        one_df,
        (one_df["company.name"].str.contains("Palo Alto Networks")) |
        (one_df["company.domain"].str.contains("paloaltonetworks.com")),
        "Palo Alto Networks",
        "Palo Alto Networks",
        "Commercial"
    )

    """ https://securityscan.academyforinternetresearch.org/ """
    identify_organization(
        one_df,
        (one_df["asn.name"].str.contains("Academy of Internet Research")) |
        (one_df["company.domain"].str.contains("deptofinternetservices.org")) |
        (one_df["hostname"].str.contains("academyforinternetresearch.org")),
        "Academy for Internet Research",
        "Acad. for Internet Research",
        "Research"
    )

    """ Shodan is harder to detect, sometimes only by hostname but sometimes not """
    identify_organization(
        one_df,
        (one_df["hostname"].str.contains("shodan")) |
        (one_df["company.domain"].str.contains("shodan")) |
        (one_df["company.name"].str.contains("Shodan")) |
        (one_df["company.name"].str.contains("SHODAN")),
        "Shodan",
        "Shodan",
        "Commercial"
    )

    """ University of Michigan, https://ece-scan.eecs.umich.edu/ """
    umich_network = ipaddress.IPv4Network("141.213.13.192/28")
    identify_organization(
        one_df,
        one_df.apply(lambda row: ipaddress.IPv4Address(row['SRC']) in umich_network, axis=1),
        "UMich ECE Research Scans",
        "UMich ECE Research Scans",
        "Research"
    )

    """ Ruhr-University Bochum NDS """
    # IP address we use for scanning: 195.37.190.88 and 195.37.190.89.
    identify_organization(
        one_df,
        (one_df["company.name"].str.contains("Ruhr-Universitaet Bochum")) |
        (one_df["SRC"] == "195.37.190.88") |
        (one_df["SRC"] == "195.37.190.89") |
        (one_df["hostname"].str.contains("nds.ruhr-uni-bochum.de")),
        "Ruhr-University Bochum NDS",
        "Ruhr University Bochum",
        "Research"
    )

    """ University of California, San Diego """
    # IP address we use for scanning: 169.228.66.212.
    identify_organization(
        one_df,
        (one_df["SRC"] == "169.228.66.212") |
        (one_df["hostname"].str.contains("research-scan.sysnet.ucsd.edu")),
        "University of California, San Diego",
        "UC San Diego",
        "Research"
    )

    """Rapid7 Project Sonar - They provide IP Ranges where scans come from
       Source Port seems to be equal than Destination Port """
    identify_organization(
        one_df,
        one_df.apply(
            lambda row: check_rapid7_ips(row['SRC']),
            axis=1
        ),
        "Rapid7 Project Sonar",
        "Rapid7",
        "Commercial"
    )

    """ Binary Edge """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("binaryedge"),
        "BinaryEdge",
        "BinaryEdge",
        "Commercial"
    )

    """ Shadowserver Foundation """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("shadowserver"),
        "Shadowserver Foundation",
        "Shadowserver",
        "Other"
    )

    """ University of Twente - Internet Transparency research project """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("please-see-measurements.internet-transparency.org"),
        "Internet Transparency Research Project",
        "Internet Transparency",
        "Research"
    )

    """ https://research.openresolve.rs/ University of Twente """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("research.openresolve.rs"),
        "DACS Research Group",
        "DACS Research Group",
        "Research"
    )

    """ RWTH Aachen """
    identify_organization(
        one_df,
        (one_df["hostname"].str.contains("comsys.rwth-aachen.de")) |
        (one_df["company.name"].str.contains("RWTH Aachen University")),
        "RWTH Aachen University",
        "RWTH Aachen",
        "Research"
    )

    """ NETSCOUT|Threat Intelligence Internet Safety Initiative, www.internet-albedo.net, www.arbor-observatory.com """
    netscout_network = ipaddress.IPv4Network("146.88.240.0/23")
    identify_organization(
        one_df,
        one_df.apply(lambda row: ipaddress.IPv4Address(row['SRC']) in netscout_network, axis=1),
        "NETSCOUT",
        "NETSCOUT",
        "Commercial"
    )

    """ alphastrike.io """
    identify_organization(
        one_df,
        (one_df["asn.asn"].str.contains("AS208843")) |
        (one_df["hostname"].str.contains(".alphastrike.io")),
        "Alpha Strike Labs",
        "Alpha Strike Labs",
        "Commercial"
    )

    """ Securitytrails """
    identify_organization(
        one_df,
        one_df["asn.asn"].str.contains("AS211607"),
        "Securitytrails",
        "Securitytrails",
        "Commercial"
    )

    """ winnti-scanner-victims-will-be-notified.threatsinkhole.com 
        scans for winnti; uses same source port for one scan """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("threatsinkhole"),
        "Winnti Scan Host",
        "Winnti Scan Host",
        "Other"
    )

    """ *.scan.bufferover.run seems belonging to https://tls.bufferover.run which scan for certificates, https://blog.erbbysam.com/ """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("bufferover.run"),
        "tls.bufferover.run",
        "tls.bufferover.run",
        "Commercial"
    )

    """ Internet Census Group """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("internet-census.org"),
        "Internet Census Group",
        "Internet Census Group",
        "Commercial"
    )

    """ http://research-scanner.com/ 
        seems to use own scaninng tools. Always sends 4 packets...
    """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("research-scanner.com"),
        "research-scanner.com",
        "research-scanner.com",
        "Research"
    )

    """ ONYPHE 
        seems to use own scanning tool, but fixed WINDOW=5840
    """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("probe.onyphe"),
        "ONYPHE",
        "ONYPHE",
        "Commercial"
    )

    """ intrinsec.com """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("intrinsec.com"),
        "Intrinsec",
        "Intrinsec",
        "Commercial"
    )

    """ LeakIX """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("scan.leakix"),
        "LeakIX",
        "LeakIX",
        "Commercial"
    )

    """ Dataprovider.com 
        they use nmap
    """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("scanning-the-internet-for-good.dataprovider.com"),
        "Dataprovider",
        "Dataprovider",
        "Commercial"
    )

    """ IPIP.NET """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("security.ipip.net"),
        "IPIP.NET",
        "IPIP.NET",
        "Commercial"
    )

    """ CyberResilience """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("cyberresilience.io"),
        "CyberResilience",
        "CyberResilience",
        "Commercial"
    )

    """ datagridsurface.com
        they use masscan and zmap
    """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("datagridsurface.com"),
        "DataGrid Surface",
        "DataGrid Surface",
        "Commercial"
    )

    """ e.g. cloud-scanner-57567cc4.internet-research-project.net
        we dont know who is behind this...
        they seem always use same source port"""
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("internet-research-project.net"),
        "internet-research-project.net",
        "internet-research-project.net",
        "Research"
    )

    """ Open Port Statistics openportstats.com 
        IoT scanner, has information about our protocols
    """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("openportstats.com"),
        "Open Port Statistics Service",
        "Open Port Statistics",
        "Other"
    )

    """ https://research.knoq.nl/ """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("research.knoq.nl"),
        "research.knoq.nl",
        "research.knoq.nl",
        "Research"
    )

    """ Georgia Institute of Technology """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("cc.gatech.edu"),
        "Georgia Institute of Technology",
        "Georgia Tech",
        "Research"
        
    )

    """  TUM """ 
    # vmott44.in.tum.de ???? """

    # vmott43.in.tum.de -- Large-scale DNS Measurements: "Time-to-time we conduct various regular and ad-hoc DNS resolutions, based on various domain toplists. Your domain is likely part of one of these lists. The ..."
    # ****** status currently unknown (website was down)
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("vmott43.in.tum.de"),
        "Technical University Munich (TUM), DNS Measurements",
        "TUM DNS Measurements",
        "Research"
    )

    # one88.cm.in.tum.de -- MPTCP adoption-in-the-wild
    # ****** status currently unknown (website was down)
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("one88.cm.in.tum.de"),
        "Technical University Munich (TUM), MPTCP Measurements",
        "TUM MPTCP Measurements",
        "Research"
    )
    
    """ GINO - Global INternet Observatory @ TUM """
    gino_network = ipaddress.IPv4Network("138.246.253.0/24")
    identify_organization(
        one_df,
        one_df.apply(
            lambda row:
                ipaddress.IPv4Address(row['SRC']) in gino_network
                or row['SRC'] == "45.33.5.55"
                or row['SRC'] == "139.162.29.117",
            axis=1
        ),
        "Global INternet Observatory (GINO) @ TUM",
        "GINO",
        "Research"
    )

    """ Criminal IP | AI SPERA """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("security.criminalip.com"),
        "Criminal IP",
        "Criminal IP",
        "Commercial"
    )

    """ Qrator or Qrator Radar? https://radar.qrator.net/ """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("qrator.net"),
        "Qrator",
        "Qrator",
        "Commercial"
    )

    """ https://optout.scanopticon.com/ """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("scanopticon.com"),
        "ScanOpticon",
        "ScanOpticon",
        "Other"
    )

    """ https://cybergreen.net/datametrics """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("scanning.cybergreen.net"),
        "CyberGreen",
        "CyberGreen",
        "Research"
    )

    """ University Cambridge https://cccc-scanner.dtg.cl.cam.ac.uk/ """
    identify_organization(
        one_df,
        (one_df["hostname"].str.contains("internet.wide.scan.using.dns-oarc.blacklist.cl.cam.ac.uk") |
        (one_df["SRC"] == "128.232.21.75")),
        "University of Cambridge",
        "University of Cambridge",
        "Research"
    )

    """ University Stanford https://research.esrg.stanford.edu , research.esrg.stanford.edu """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("research.esrg.stanford.edu"),
        "Stanford University",
        "Stanford University",
        "Research"
    )

    """ http://researchscanner100.eecs.berkeley.edu/ University of California at Berkeley """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("eecs.berkeley.edu"),
        "Berkeley Research Scanning",
        "UC Berkeley",
        "Research"
    )

    """ http://zbuff-research-scan.colorado.edu/ University of Colorado """
    identify_organization(
        one_df,
        (one_df["hostname"].str.contains("research-scan.colorado.edu")) |
        (one_df["SRC"] == "192.12.240.40"),
        "University of Colorado",
        "University of Colorado",
        "Research"
    )

    """ team-cymru.org, https://dnsresearch.cymru.com/ """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("dnsresearch.cymru.com"),
        "Team Cymru DNS Measurements",
        "Team Cymru DNS",
        "Commercial"
    )

    """ team-cymru.org, https://ntpresearch2.cymru.com/ """
    identify_organization(
        one_df,
        (one_df["hostname"].str.contains("ntpresearch.cymru.com")) | (one_df["SRC"] == "216.31.0.17"),
        "Team Cymru NTP Measurements",
        "Team Cymru NTP",
        "Commercial"
    )

    """ internettl.org, website currently down, https://web.archive.org/web/20210921015530/http://www.internettl.org/ """ # ******
    # https://viz.greynoise.io/tag/internettl?days=3; "InterneTTL, a security research organization that regularly mass-scans the Internet."
    identify_organization(
        one_df,
        one_df["hostname"].astype(str).str.contains("internettl.org"),
        "InterneTTL",
        "InterneTTL",
        "Research"
    )

    """ FH Münster https://fb02itsscan06.fh-muenster.de/ """
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("fb02itsscan06.fh-muenster.de"),
        "University of Münster",
        "University of Münster",
        "Research"
    )

    """ Stretchoid https://stretchoid.com """
    identify_organization(
        one_df,
        one_df["hostname"].astype(str).str.contains("stretchoid.com"),
        "Stretchoid",
        "Stretchoid",
        "Other"
    )

    """ internetmeasurementresearch.com (IMR) """
    identify_organization(
        one_df,
        one_df["asn.domain"].astype(str).str.contains("internetmeasurementresearch.com"),
        "internetmeasurementresearch.com",
        "IMR",
        "Research"
    )
    
    """ http://www.netsecscan.net -- This is a non-malicious academic research scanning node"""
    identify_organization(
        one_df,
        one_df["hostname"].astype(str).str.contains("netsecscan.net"),
        "netsecscan.net",
        "netsecscan.net",
        "Research"
    )

    """ Max-Planck-Institut fuer Informatik, https://inet-research-scan-3.mpi-inf.mpg.de  """
    # https://inet-scan-2.mpi-inf.mpg.de
    identify_organization(
        one_df,
        one_df["hostname"].astype(str).str.contains(".mpg.de"),
        "Max Planck Institute for Informatics",
        "MPI for Informatics",
        "Research"
    )
    

    ######## HOSTING ORGANIZATIONS ########
    # google
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("bc.googleusercontent.com"),
        "Google LLC",
        "",
        "",
        OrganizationType.HOSTING_ORGANIZATION
    )

    # linode
    identify_organization(
        one_df,
        one_df["hostname"].str.contains(".ip.linodeusercontent.com"),
        "Akamai Connected Cloud / Linode",
        "",
        "",
        OrganizationType.HOSTING_ORGANIZATION
    )

    # Tamatiya EOOD / 4vendeta.com
    identify_organization(
        one_df,
        (one_df["hostname"].str.contains(".4vendeta.com")) |
        (one_df["asn.domain"].str.contains(".4vendeta.com")) |
        (one_df["company.name"].str.contains("Tamatiya EOOD")),
        "Tamatiya EOOD / 4vendeta.com",
        "",
        "",
        OrganizationType.HOSTING_ORGANIZATION
    )

    # pfcloud.io
    identify_organization(
        one_df,
        one_df["hostname"].str.contains(".pfcloud.io"),
        "pfcloud.io / Aggros Operations Ltd.",
        "",
        "",
        OrganizationType.HOSTING_ORGANIZATION
    )

    # amazonaws
    identify_organization(
        one_df,
        (one_df["hostname"].str.contains("amazonaws.com")) |
        (one_df["hostname"].str.contains(".compute.amazonaws.com")) |
        (one_df["hostname"].str.contains(".awsglobalaccelerator.com")),
        "Amazon.com, Inc.",
        "",
        "",
        OrganizationType.HOSTING_ORGANIZATION
    )

    # hinet-ip.hinet.net
    identify_organization(
        one_df,
        one_df["hostname"].str.contains("hinet-ip.hinet.net"),
        "Chunghwa Telecom Co.,Ltd.",
        "",
        "",
        OrganizationType.HOSTING_ORGANIZATION
    )

    # ovh cloud
    identify_organization(
        one_df,
        one_df["asn.domain"].str.contains("ovhcloud.com"),
        "OVH Cloud",
        "",
        "",
        OrganizationType.HOSTING_ORGANIZATION
    )
    return one_df

def manual_tool_identification_fixes(df: pd.DataFrame) -> None:
    """Some organizations use different tools than identified using the automatic identification"""

    # Censys uses own engine based on zmap, because the creators of zmap started censys...they are identified as nmap and some masscan..?
    censys_tool_matches = ((df["company.name"].str.contains("Censys")) | (df["asn.name"].str.contains("Censys")))
    df["tool"] = np.where(
        censys_tool_matches,
        'other',
        df['tool']
    )
    logging.info(f'Replacing tool of Censys: {censys_tool_matches.sum()}')
    
    # there is one random packet with window size '2048' and therefore detected wrongly as nmap
    shodan_tool_matches = (df["hostname"].str.contains("shodan")) & (df["tool"].astype(str).str.contains("nmap"))
    df["tool"] = np.where(
        shodan_tool_matches,
        'other',
        df['tool']
    )
    logging.info(f'Replacing tool of Shodan: {shodan_tool_matches.sum()}')
