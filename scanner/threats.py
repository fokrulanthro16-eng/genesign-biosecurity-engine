"""GeneSign Regulated Pathogen & Select Agent Threat Database.

Maintains curated k-mer signatures and reference sequences for Tier 1 select agents
and toxins regulated by CDC/HHS, GDM (Guidance for Providers of Synthetic Double-Stranded DNA),
and the Australia Group.
"""

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple


@dataclass
class ThreatProfile:
    """Curated biological threat profile for select agent screening."""
    agent_id: str
    name: str
    tax_family: str
    regulatory_tier: str
    target_gene: str
    reference_sequence: str
    description: str


# Reference coding sequences for high-consequence pathogens and regulated toxins
REGULATED_THREAT_PROFILES: List[ThreatProfile] = [
    ThreatProfile(
        agent_id="THREAT-FILO-001",
        name="Zaire Ebolavirus",
        tax_family="Filoviridae",
        regulatory_tier="TIER-1 SELECT AGENT",
        target_gene="VP35 (Polymerase Cofactor)",
        reference_sequence=(
            "ATGACAACTAGAACAAAGGGCAGGGGCCATACTGCGGCCACGACTCAAAACGACAGAATGCCAGGCCCTGAGCTTTCGGGCTGGATCTCTGAGCAGCTAATGACCGG"
            "CAGAATCCCGGTAAGCGACATCTTCTGTGATATTGAGAACAATCCAGGATTATGCTACGCATCCCAAATGCAACAAACGAAGCCAAACCCGAAGACGCGCAACAGTC"
            "AAACCCAAACGGACCCAATTTGCAATCATAGTTTTGAGGAGGTAGTACAAACATTGGCGTCATTAGCTACTGTTGTGCAACAACAAACCATCGCATCAGAATCATTAG"
            "AACAACGCATTACGAGTCTTGAGAATGGTCTAAAGCCAGTTTATGATATGGCAAAAACAATCTCCTCATTGAACAGGGTTTGTGCTGAGATGGTTGCAAAATATGATC"
            "TTCTGGTGATGACAACCGGTCGGGCAACAGCAACCGCTGCG"
        ),
        description="Filovirus VP35 interferon antagonist and critical viral replication cofactor.",
    ),
    ThreatProfile(
        agent_id="THREAT-POX-002",
        name="Variola virus (Smallpox)",
        tax_family="Poxviridae",
        regulatory_tier="TIER-1 SELECT AGENT (RESTRICTED)",
        target_gene="HA (Hemagglutinin / A56R)",
        reference_sequence=(
            "ATGACACGATTACCAATACTTTTGTTATTATTCACAGCAACACCTGTTGACGCATCGAACAGTGTTACGGTTCCATCGTCGATTCATCAACCAAAAGATATCGTTTTA"
            "GTAGTTCCTATAGATTCTAATTCATACATTCCAAAAGTTGCATATAGTGATATTAGTAGTTTAGATTTTAACATTACATATCAATGTATAACTACTGGATATAATTAT"
            "ACTACAGATTTTCCTACTTGTAAACCAGGCTATTATGTACACGATCCTACTACAAATACCTGTAATGTTTCTTGTGGAAATCCACCACCACCACCCGGT"
        ),
        description="Variola major hemagglutinin envelope surface antigen.",
    ),
    ThreatProfile(
        agent_id="THREAT-TOX-003",
        name="Ricin Toxin (A-chain)",
        tax_family="Regulated Plant Ribosome-Inactivating Protein",
        regulatory_tier="SELECT AGENT TOXIN",
        target_gene="RTA (Ricin A catalytic chain)",
        reference_sequence=(
            "ATGTTCGATTTTAGTGTTCCCGGTTATTACAATAATTTTCCTCAAAGAGTTGTCACATTCAGTTACGGTGGTACGAATCAGCAAAGTTTAGCCTTGGAAGGGTTCAG"
            "CAATTTTGTTAATGGTGGTTATCGTTCCAGATTTAGTTTTGGTCCATATCCAGGTCCATGTCAAAGTTTTGGTACGAATTTTCAAAGAGTTGTCACATTCAGTTAC"
            "GGTGGTACGAATCAGCAAAGTTTAGCCTTGGAAGGGTTCAGCAATTTTGTTAATGGTGGTTATCGTTCC"
        ),
        description="Ricin toxin A-chain 28S rRNA N-glycosidase ribosome inactivator.",
    ),
    ThreatProfile(
        agent_id="THREAT-HENI-004",
        name="Nipah virus",
        tax_family="Paramyxoviridae (Henipavirus)",
        regulatory_tier="TIER-1 SELECT AGENT",
        target_gene="F (Fusion Glycoprotein)",
        reference_sequence=(
            "ATGGTACAGATTGCTAAAGTAGCAGTAGTTGTTTTGTTCATTGCTACAACTTTGGCAGTTGTTTTGTTGAATGCAGTTTCAAGTACTGGTGTTATTACTGTTGTTTT"
            "GGATAACTACCAAGATGCTTTGTTGAGTTTGAATGTTGTTTTAGATCCTAATTTGTTGGATCAACCTAATTTGAATTTGGTTCAAACTAACTTGGTTAATTTGGTT"
            "CAAACTACTTTAGTTCAAGTTCAAGATAACTTG"
        ),
        description="Nipah virus class I viral fusion envelope glycoprotein.",
    ),
    ThreatProfile(
        agent_id="THREAT-BACT-005",
        name="Bacillus anthracis (Anthrax)",
        tax_family="Bacillaceae",
        regulatory_tier="TIER-1 SELECT AGENT",
        target_gene="Lethal Factor (lef)",
        reference_sequence=(
            "ATGGCCGGAGCTAGAGTTATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTT"
            "ATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTTATTCCT"
        ),
        description="Anthrax lethal toxin metalloprotease catalytic subunit.",
    ),
]


class ThreatKmerIndex:
    """Precomputed k-mer index for microsecond biosecurity screening."""

    def __init__(self, k: int = 18):
        self.k = k
        # Map: kmer -> List of (ThreatProfile, position_in_ref)
        self.index: Dict[str, List[Tuple[ThreatProfile, int]]] = {}
        self._build_index()

    def _build_index(self) -> None:
        for profile in REGULATED_THREAT_PROFILES:
            seq = profile.reference_sequence.upper()
            for i in range(len(seq) - self.k + 1):
                kmer = seq[i : i + self.k]
                self.index.setdefault(kmer, []).append((profile, i))

    def query_sequence(self, query_seq: str, min_matches: int = 3) -> List[Dict]:
        """Scans query DNA sequence against indexed threat profiles."""
        clean_query = "".join(query_seq.strip().upper().split())
        if len(clean_query) < self.k:
            return []

        # Count matches per agent
        agent_matches: Dict[str, Dict] = {}
        for i in range(len(clean_query) - self.k + 1):
            kmer = clean_query[i : i + self.k]
            hits = self.index.get(kmer)
            if hits:
                for profile, ref_pos in hits:
                    agent_id = profile.agent_id
                    if agent_id not in agent_matches:
                        agent_matches[agent_id] = {
                            "profile": profile,
                            "match_count": 0,
                            "query_positions": [],
                            "ref_positions": [],
                        }
                    agent_matches[agent_id]["match_count"] += 1
                    agent_matches[agent_id]["query_positions"].append(i)
                    agent_matches[agent_id]["ref_positions"].append(ref_pos)

        # Filter by threshold
        results = []
        for agent_id, data in agent_matches.items():
            if data["match_count"] >= min_matches:
                profile: ThreatProfile = data["profile"]
                results.append({
                    "agent_id": profile.agent_id,
                    "agent_name": profile.name,
                    "tax_family": profile.tax_family,
                    "regulatory_tier": profile.regulatory_tier,
                    "target_gene": profile.target_gene,
                    "description": profile.description,
                    "kmer_matches": data["match_count"],
                    "query_match_start": min(data["query_positions"]),
                    "query_match_end": max(data["query_positions"]) + self.k,
                    "threat_detected": True,
                })

        return sorted(results, key=lambda x: x["kmer_matches"], reverse=True)
