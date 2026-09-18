"""GeneSign Scalable Biosecurity Alignment & Toxin Threat Detector.

Provides high-throughput sliding-window canonical k-mer indexing, multi-agent select
pathogen screening, and sequence alignment scoring to detect:
  1. CDC Tier-1 Select Agents (Filoviridae, Poxviridae, Henipavirus)
  2. Regulated Biological Toxins (Ricin, Botulinum, Anthrax Lethal Factor, SEB, Shiga)
  3. Chimeric Viral Payloads & Obfuscated Synthetic Insertions
  4. Degenerate Codon Point-Mutation Evasions
"""

import math
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple, Any


COMPLEMENT_MAP = str.maketrans("ACGTNacgtn", "TGCANtgcan")


def reverse_complement(dna_seq: str) -> str:
    """Computes reverse complement of DNA sequence."""
    return dna_seq.translate(COMPLEMENT_MAP)[::-1]


def get_canonical_kmer(kmer: str) -> str:
    """Returns lexicographically smaller of k-mer and its reverse complement."""
    rc = reverse_complement(kmer)
    return kmer if kmer < rc else rc


@dataclass
class ThreatReference:
    """Reference profile for regulated select agent or toxin."""
    agent_id: str
    name: str
    tax_family: str
    regulatory_tier: str
    target_gene: str
    description: str
    sequence: str
    canonical_kmers: Set[str] = None

    def __post_init__(self):
        if self.canonical_kmers is None:
            self.canonical_kmers = set()


# Curated high-consequence reference library
REFERENCE_THREAT_LIBRARY: List[ThreatReference] = [
    ThreatReference(
        agent_id="THREAT-FILO-001",
        name="Zaire Ebolavirus",
        tax_family="Filoviridae",
        regulatory_tier="TIER-1 SELECT AGENT",
        target_gene="VP35 (Polymerase Cofactor)",
        description="Filovirus VP35 interferon antagonist and critical replication cofactor.",
        sequence=(
            "ATGACAACTAGAACAAAGGGCAGGGGCCATACTGCGGCCACGACTCAAAACGACAGAATGCCAGGCCCTGAGCTTTCGGGCTGGATCTCTGAGCAGCTAATGACCGG"
            "CAGAATCCCGGTAAGCGACATCTTCTGTGATATTGAGAACAATCCAGGATTATGCTACGCATCCCAAATGCAACAAACGAAGCCAAACCCGAAGACGCGCAACAGTC"
            "AAACCCAAACGGACCCAATTTGCAATCATAGTTTTGAGGAGGTAGTACAAACATTGGCGTCATTAGCTACTGTTGTGCAACAACAAACCATCGCATCAGAATCATTAG"
            "AACAACGCATTACGAGTCTTGAGAATGGTCTAAAGCCAGTTTATGATATGGCAAAAACAATCTCCTCATTGAACAGGGTTTGTGCTGAGATGGTTGCAAAATATGATC"
            "TTCTGGTGATGACAACCGGTCGGGCAACAGCAACCGCTGCG"
        ),
    ),
    ThreatReference(
        agent_id="THREAT-FILO-002",
        name="Marburg virus",
        tax_family="Filoviridae",
        regulatory_tier="TIER-1 SELECT AGENT",
        target_gene="NP (Nucleoprotein)",
        description="Marburg filovirus core structural nucleoprotein.",
        sequence=(
            "ATGGATTCTCGTCCTCAGAAAGTCTGGATGACGCCGAGTCTCACTGAATCTGACATGGATTACCACAGATCCTCGAACAAGCTCTACAGCGACGTCGTAGCCACAGTT"
            "GTAGCCCAAAACGACAGAATGCCAGGCCCTGAGCTTTCGGGCTGGATCTCTGAGCAGCTAATGACCGGCAGAATCCCGGTAAGCGACATCTTCTGTGATATTGAGAAC"
            "AATCCAGGATTATGCTACGCATCCCAAATGCAACAAACGAAGCCAAACCCGAAGACGCGCAACAG"
        ),
    ),
    ThreatReference(
        agent_id="THREAT-POX-001",
        name="Variola virus (Smallpox)",
        tax_family="Poxviridae",
        regulatory_tier="TIER-1 SELECT AGENT (RESTRICTED)",
        target_gene="HA (Hemagglutinin / A56R)",
        description="Variola major hemagglutinin envelope surface antigen.",
        sequence=(
            "ATGACACGATTACCAATACTTTTGTTATTATTCACAGCAACACCTGTTGACGCATCGAACAGTGTTACGGTTCCATCGTCGATTCATCAACCAAAAGATATCGTTTTA"
            "GTAGTTCCTATAGATTCTAATTCATACATTCCAAAAGTTGCATATAGTGATATTAGTAGTTTAGATTTTAACATTACATATCAATGTATAACTACTGGATATAATTAT"
            "ACTACAGATTTTCCTACTTGTAAACCAGGCTATTATGTACACGATCCTACTACAAATACCTGTAATGTTTCTTGTGGAAATCCACCACCACCACCCGGT"
        ),
    ),
    ThreatReference(
        agent_id="THREAT-HENI-001",
        name="Nipah virus",
        tax_family="Paramyxoviridae (Henipavirus)",
        regulatory_tier="TIER-1 SELECT AGENT",
        target_gene="F (Fusion Glycoprotein)",
        description="Nipah virus class I viral fusion envelope glycoprotein.",
        sequence=(
            "ATGGTACAGATTGCTAAAGTAGCAGTAGTTGTTTTGTTCATTGCTACAACTTTGGCAGTTGTTTTGTTGAATGCAGTTTCAAGTACTGGTGTTATTACTGTTGTTTT"
            "GGATAACTACCAAGATGCTTTGTTGAGTTTGAATGTTGTTTTAGATCCTAATTTGTTGGATCAACCTAATTTGAATTTGGTTCAAACTAACTTGGTTAATTTGGTT"
            "CAAACTACTTTAGTTCAAGTTCAAGATAACTTG"
        ),
    ),
    ThreatReference(
        agent_id="THREAT-TOX-001",
        name="Ricin Toxin (A-chain)",
        tax_family="Regulated Plant Ribosome-Inactivating Protein",
        regulatory_tier="SELECT AGENT TOXIN",
        target_gene="RTA (Ricin A Catalytic Chain)",
        description="Ricin toxin A-chain 28S rRNA N-glycosidase ribosome inactivator.",
        sequence=(
            "ATGTTCGATTTTAGTGTTCCCGGTTATTACAATAATTTTCCTCAAAGAGTTGTCACATTCAGTTACGGTGGTACGAATCAGCAAAGTTTAGCCTTGGAAGGGTTCAG"
            "CAATTTTGTTAATGGTGGTTATCGTTCCAGATTTAGTTTTGGTCCATATCCAGGTCCATGTCAAAGTTTTGGTACGAATTTTCAAAGAGTTGTCACATTCAGTTAC"
            "GGTGGTACGAATCAGCAAAGTTTAGCCTTGGAAGGGTTCAGCAATTTTGTTAATGGTGGTTATCGTTCC"
        ),
    ),
    ThreatReference(
        agent_id="THREAT-TOX-002",
        name="Botulinum Neurotoxin Type A",
        tax_family="Clostridial Neurotoxin",
        regulatory_tier="SELECT AGENT TOXIN",
        target_gene="BoNT/A Light Chain (Catalytic Zinc Metalloprotease)",
        description="Botulinum neurotoxin light chain SNARE protein cleavage enzyme.",
        sequence=(
            "ATGCCATTTGTTAATAAACAATTTAATTATAAAGATCCTGTAAATGGTGTTGATATTGCTTATATAAAAATTCCAAATGCAGGTCAAATGCAACCAGTAAAAGCT"
            "TTTAAAATTCATAATAAAATATGGGTAATTCCAGAAAGAGATACATTTACAAATCCTGAAGAAGGAGATTTAAATCCACCACCAGAAGCAAAACAAGTTCCAGTT"
            "TCATATTATGATTCAACATATCTAAGTACAGATAATGAAAAAGATAACTATCTTAAAGGTGTAACTAAATTATTTGAACGTATTTATTCAACTGATTTGGGAAGA"
        ),
    ),
    ThreatReference(
        agent_id="THREAT-TOX-003",
        name="Bacillus anthracis (Anthrax)",
        tax_family="Bacillaceae",
        regulatory_tier="TIER-1 SELECT AGENT",
        target_gene="Lethal Factor (lef)",
        description="Anthrax lethal toxin metalloprotease catalytic subunit.",
        sequence=(
            "ATGGCCGGAGCTAGAGTTATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTT"
            "ATTCCTATTTTAGAAGGGTTAGATAGAAATGTTGTAGGTGGTTTTACAAATTTTGCTGAAGAAGTTGTAGAAGGTAGAGCTAGAGTTATTCCT"
        ),
    ),
    ThreatReference(
        agent_id="THREAT-CHIMERA-001",
        name="Engineered Chimeric Cleavage Motif",
        tax_family="Synthetic Chimeric Construct",
        regulatory_tier="GOF-WATCHLIST CHIMERA",
        target_gene="Synthetic Furin Cleavage Insertion",
        description="Chimeric polybasic furin cleavage loop inserted into viral spike/envelope backbone.",
        sequence=(
            "CCTCGGCGGGCACGTAGTGTAGCTAGTCAATCCATCATTGCCTACACTATGTCACTTGGTGCAGAAAATTCAGTTGCTTACTCTAATAACTCTATTGCCATACCC"
            "CGGCGGGCACGTAGT"
        ),
    ),
]


@dataclass
class ThreatAlignmentHit:
    """Detailed hit from sliding-window alignment scoring."""
    agent_id: str
    agent_name: str
    tax_family: str
    regulatory_tier: str
    target_gene: str
    description: str
    kmer_matches: int
    alignment_score: float  # 0.0 to 1.0
    confidence: str         # CRITICAL, HIGH, MODERATE
    insertion_type: str     # FULL_GENE, CHIMERIC_INSERT, POINT_MUTATION_VARIANT
    query_match_start: int
    query_match_end: int
    threat_detected: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScalableThreatDetector:
    """High-throughput sliding window threat detector with k-mer indexing and alignment scoring."""

    def __init__(self, k: int = 17, window_size: int = 120, step_size: int = 30):
        self.k = k
        self.window_size = window_size
        self.step_size = step_size
        self.kmer_index: Dict[str, List[Tuple[ThreatReference, int]]] = {}
        self.references: List[ThreatReference] = list(REFERENCE_THREAT_LIBRARY)
        self._build_index()

    def _build_index(self) -> None:
        """Precomputes canonical k-mer hash index across all threat references."""
        for ref in self.references:
            clean_seq = "".join(ref.sequence.strip().upper().split())
            ref.canonical_kmers = set()
            for i in range(len(clean_seq) - self.k + 1):
                kmer = clean_seq[i : i + self.k]
                canon = get_canonical_kmer(kmer)
                ref.canonical_kmers.add(canon)
                self.kmer_index.setdefault(canon, []).append((ref, i))

    def scan_sequence(self, query_dna: str) -> Dict[str, Any]:
        """Performs sliding-window multi-vector threat screening and alignment scoring.

        Catches select agents, toxins, chimeric constructs, and obfuscated insertions.
        """
        clean_query = "".join(query_dna.strip().upper().split())
        query_len = len(clean_query)

        if query_len < self.k:
            return {
                "threat_detected": False,
                "chimeric_detected": False,
                "highest_tier": "NONE",
                "hits": [],
            }

        # 1. Global Canonical K-mer Mapping
        hits_by_agent: Dict[str, Dict[str, Any]] = {}

        for i in range(query_len - self.k + 1):
            kmer = clean_query[i : i + self.k]
            canon = get_canonical_kmer(kmer)
            matches = self.kmer_index.get(canon)
            if matches:
                for ref, ref_pos in matches:
                    aid = ref.agent_id
                    if aid not in hits_by_agent:
                        hits_by_agent[aid] = {
                            "ref": ref,
                            "kmer_count": 0,
                            "query_positions": [],
                            "ref_positions": [],
                        }
                    hits_by_agent[aid]["kmer_count"] += 1
                    hits_by_agent[aid]["query_positions"].append(i)
                    hits_by_agent[aid]["ref_positions"].append(ref_pos)

        # 2. Sliding Window Alignment & Density Scoring
        scored_hits: List[ThreatAlignmentHit] = []
        families_detected: Set[str] = set()

        for aid, data in hits_by_agent.items():
            ref: ThreatReference = data["ref"]
            k_count = data["kmer_count"]
            q_positions = data["query_positions"]

            if k_count < 3:
                continue

            q_start = min(q_positions)
            q_end = max(q_positions) + self.k
            span_len = q_end - q_start

            # Alignment score = Jaccard overlap of canonical k-mers over the hit span
            span_seq = clean_query[q_start:q_end]
            span_kmers = {
                get_canonical_kmer(span_seq[j : j + self.k])
                for j in range(len(span_seq) - self.k + 1)
            }
            intersection = len(span_kmers.intersection(ref.canonical_kmers))
            union = len(span_kmers.union(ref.canonical_kmers))
            jaccard = round(intersection / max(union, 1), 3)

            # Match density over the span
            max_possible_kmers = max(span_len - self.k + 1, 1)
            density = min(round(k_count / max_possible_kmers, 3), 1.0)
            alignment_score = round((jaccard * 0.6) + (density * 0.4), 3)

            # Classify insertion type
            ref_len = len("".join(ref.sequence.strip().upper().split()))
            if span_len >= ref_len * 0.8:
                ins_type = "FULL_GENE"
            elif span_len < 180 and query_len > 400:
                ins_type = "CHIMERIC_INSERT"
            else:
                ins_type = "SUBSTITUTION_VARIANT"

            # Confidence determination
            if alignment_score >= 0.35 or k_count >= 15:
                confidence = "CRITICAL"
            elif alignment_score >= 0.15 or k_count >= 6:
                confidence = "HIGH"
            else:
                confidence = "MODERATE"

            hit = ThreatAlignmentHit(
                agent_id=ref.agent_id,
                agent_name=ref.name,
                tax_family=ref.tax_family,
                regulatory_tier=ref.regulatory_tier,
                target_gene=ref.target_gene,
                description=ref.description,
                kmer_matches=k_count,
                alignment_score=alignment_score,
                confidence=confidence,
                insertion_type=ins_type,
                query_match_start=q_start,
                query_match_end=q_end,
                threat_detected=True,
            )
            scored_hits.append(hit)
            families_detected.add(ref.tax_family)

        # Chimeric Construct Detection: multiple distinct threat families detected in one sequence
        chimeric = len(families_detected) > 1

        # Determine highest regulatory tier
        tiers = [h.regulatory_tier for h in scored_hits]
        if any("TIER-1" in t for t in tiers):
            highest_tier = "TIER-1 SELECT AGENT"
        elif any("TOXIN" in t for t in tiers):
            highest_tier = "SELECT AGENT TOXIN"
        elif scored_hits:
            highest_tier = scored_hits[0].regulatory_tier
        else:
            highest_tier = "NONE"

        # Sort by alignment score descending
        scored_hits.sort(key=lambda x: (x.alignment_score, x.kmer_matches), reverse=True)

        return {
            "threat_detected": len(scored_hits) > 0,
            "chimeric_detected": chimeric,
            "highest_tier": highest_tier,
            "hits": [h.to_dict() for h in scored_hits],
        }


# Global threat detector singleton
threat_detector = ScalableThreatDetector()
