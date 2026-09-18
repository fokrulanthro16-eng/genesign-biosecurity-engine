"""GeneSign Biological and Steganographic Constants.

Defines the standard IUPAC genetic code, synonymous codon mappings,
zero-drift carrier codon pairs, and regulated restriction enzyme
recognition sequences.
"""

from typing import Dict, List, Tuple

# Standard Genetic Code (Universal)
CODON_TO_AA: Dict[str, str] = {
    # Phenylalanine & Leucine
    "TTT": "F", "TTC": "F", "TTA": "L", "TTG": "L",
    # Leucine
    "CTT": "L", "CTC": "L", "CTA": "L", "CTG": "L",
    # Isoleucine & Methionine (Start)
    "ATT": "I", "ATC": "I", "ATA": "I", "ATG": "M",
    # Valine
    "GTT": "V", "GTC": "V", "GTA": "V", "GTG": "V",
    # Serine
    "TCT": "S", "TCC": "S", "TCA": "S", "TCG": "S",
    # Proline
    "CCT": "P", "CCC": "P", "CCA": "P", "CCG": "P",
    # Threonine
    "ACT": "T", "ACC": "T", "ACA": "T", "ACG": "T",
    # Alanine
    "GCT": "A", "GCC": "A", "GCA": "A", "GCG": "A",
    # Tyrosine & Stop
    "TAT": "Y", "TAC": "Y", "TAA": "*", "TAG": "*",
    # Histidine & Glutamine
    "CAT": "H", "CAC": "H", "CAA": "Q", "CAG": "Q",
    # Asparagine & Lysine
    "AAT": "N", "AAC": "N", "AAA": "K", "AAG": "K",
    # Aspartate & Glutamate
    "GAT": "D", "GAC": "D", "GAA": "E", "GAG": "E",
    # Cysteine, Stop & Tryptophan
    "TGT": "C", "TGC": "C", "TGA": "*", "TGG": "W",
    # Serine & Arginine
    "AGT": "S", "AGC": "S", "AGA": "R", "AGG": "R",
    # Arginine
    "CGT": "R", "CGC": "R", "CGA": "R", "CGG": "R",
    # Glycine
    "GGT": "G", "GGC": "G", "GGA": "G", "GGG": "G",
}

# Reverse mapping: Amino Acid -> List of synonymous codons
AA_TO_CODONS: Dict[str, List[str]] = {}
for _codon, _aa in CODON_TO_AA.items():
    AA_TO_CODONS.setdefault(_aa, []).append(_codon)

# Zero-Drift Synonymous Carrier Pairs (codon_bit0, codon_bit1)
# Each pair codes for identical amino acid AND has identical GC count,
# ensuring mathematical guarantee of 0.000% GC drift.
ZERO_DRIFT_PAIRS: List[Tuple[str, str]] = [
    # Valine (V)
    ("GTT", "GTA"),  # 1 GC
    ("GTC", "GTG"),  # 2 GC
    # Proline (P)
    ("CCT", "CCA"),  # 2 GC
    ("CCC", "CCG"),  # 3 GC
    # Threonine (T)
    ("ACT", "ACA"),  # 1 GC
    ("ACC", "ACG"),  # 2 GC
    # Alanine (A)
    ("GCT", "GCA"),  # 2 GC
    ("GCC", "GCG"),  # 3 GC
    # Glycine (G)
    ("GGT", "GGA"),  # 2 GC
    ("GGC", "GGG"),  # 3 GC
    # Leucine (L)
    ("CTT", "CTA"),  # 1 GC
    ("CTC", "CTG"),  # 2 GC
    # Serine (S)
    ("TCT", "TCA"),  # 1 GC
    ("TCC", "TCG"),  # 2 GC
    # Arginine (R)
    ("CGT", "CGA"),  # 2 GC
    ("CGC", "CGG"),  # 3 GC
]

CARRIER_CODON_TO_BIT: Dict[str, str] = {}
CARRIER_CODON_PARTNER: Dict[str, str] = {}
for _c0, _c1 in ZERO_DRIFT_PAIRS:
    CARRIER_CODON_TO_BIT[_c0] = "0"
    CARRIER_CODON_TO_BIT[_c1] = "1"
    CARRIER_CODON_PARTNER[_c0] = _c1
    CARRIER_CODON_PARTNER[_c1] = _c0

# Prohibited restriction enzyme sites to guard against in synthesis
RESTRICTION_SITES: Dict[str, str] = {
    "EcoRI": "GAATTC",
    "BamHI": "GGATCC",
    "HindIII": "AAGCTT",
    "NotI": "GCGGCCGC",
    "XhoI": "CTCGAG",
    "NdeI": "CATATG",
    "PstI": "CTGCAG",
    "SalI": "GTCGAC",
}

# GeneSign Framing Magic Sync Word (8 bits: 0xA5 = 10100101)
MAGIC_SYNC_BITS = "10100101"
MAGIC_SYNC_BYTE = 0xA5
PROTOCOL_VERSION = 1
