"""GeneSign Fragment Assembly De-anonymization & Overhang Reconstruction Engine.

Cross-references sliding-window orders across synthesis providers and customer queues
to detect distributed synthesis evasion attacks. Identifies cohesive overhangs, Gibson
assembly homologies, and Golden Gate restriction scars, assembling fragmented sub-sequences
into reconstructed contigs and evaluating them against high-consequence biosecurity indices.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Optional, Set, Tuple, Any

from engine.threat_detector import threat_detector, ScalableThreatDetector


@dataclass
class FragmentOrder:
    """Individual sequence fragment submitted in a commercial synthesis order."""
    order_id: str
    record_id: str
    sequence: str
    customer_id: str
    provider_id: str
    timestamp: str
    length_nt: int
    sequence_hash: str


@dataclass
class AssemblyOverlap:
    """Detected cohesive overlap / homology junction between two orders."""
    source_order_id: str
    target_order_id: str
    overlap_sequence: str
    overlap_length_nt: int
    assembly_type: str  # HOMOLOGY_OVERHANG, GIBSON_OVERLAP, STICKY_END


@dataclass
class ReconstructedThreatContig:
    """A composite sequence reconstructed from fragmented distributed orders."""
    contig_id: str
    assembled_sequence: str
    assembled_length_nt: int
    participating_order_ids: List[str]
    participating_customers: List[str]
    overlap_junctions: List[Dict[str, Any]]
    threat_detected: bool
    agent_name: Optional[str]
    regulatory_tier: Optional[str]
    confidence: Optional[str]
    status_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SplitOrderGraphAssembler:
    """Graph assembler and threat de-anonymization engine for distributed DNA orders."""

    def __init__(
        self,
        min_overlap: int = 15,
        detector: Optional[ScalableThreatDetector] = None,
        max_sliding_window_orders: int = 200,
    ):
        self.min_overlap = min_overlap
        self.detector = detector or threat_detector
        self.max_orders = max_sliding_window_orders
        self.order_pool: List[FragmentOrder] = []

    def clear(self) -> None:
        """Clears sliding window memory."""
        self.order_pool.clear()

    def add_order(
        self,
        order_id: str,
        sequence: str,
        customer_id: str = "CUST-DEFAULT",
        provider_id: str = "TWIST",
        record_id: Optional[str] = None,
    ) -> FragmentOrder:
        """Appends an order to the active cross-order sliding window."""
        clean = "".join(sequence.strip().upper().split())
        seq_hash = hashlib.sha256(clean.encode()).hexdigest()
        frag = FragmentOrder(
            order_id=order_id,
            record_id=record_id or order_id,
            sequence=clean,
            customer_id=customer_id,
            provider_id=provider_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            length_nt=len(clean),
            sequence_hash=seq_hash,
        )
        self.order_pool.append(frag)
        if len(self.order_pool) > self.max_orders:
            self.order_pool.pop(0)
        return frag

    def find_overlap(self, seq_a: str, seq_b: str) -> Optional[Tuple[str, int]]:
        """Finds maximum suffix-prefix overlap between seq_a and seq_b of length >= min_overlap."""
        max_k = min(len(seq_a), len(seq_b))
        for k in range(max_k, self.min_overlap - 1, -1):
            if seq_a[-k:] == seq_b[:k]:
                return (seq_a[-k:], k)
        return None

    def reconstruct_contigs(self, orders: Optional[List[FragmentOrder]] = None) -> List[ReconstructedThreatContig]:
        """Builds directed overlap graph across orders and reconstructs assembled contigs."""
        pool = orders if orders is not None else self.order_pool
        if len(pool) < 2:
            return []

        # Step 1: Detect pairwise overlaps
        adjacency: Dict[str, List[Tuple[str, str, int]]] = {o.order_id: [] for o in pool}
        orders_by_id = {o.order_id: o for o in pool}

        for i, a in enumerate(pool):
            for j, b in enumerate(pool):
                if i == j:
                    continue
                match = self.find_overlap(a.sequence, b.sequence)
                if match:
                    overlap_seq, overlap_len = match
                    adjacency[a.order_id].append((b.order_id, overlap_seq, overlap_len))

        # Step 2: Traverse paths to form assembled sequences
        assembled_paths: List[List[str]] = []

        def dfs(current_id: str, visited: List[str]):
            extended = False
            for nxt_id, _, _ in adjacency.get(current_id, []):
                if nxt_id not in visited:
                    extended = True
                    dfs(nxt_id, visited + [nxt_id])
            if not extended and len(visited) > 1:
                assembled_paths.append(visited)

        for o in pool:
            dfs(o.order_id, [o.order_id])

        # De-duplicate sub-paths
        longest_paths = []
        assembled_paths.sort(key=len, reverse=True)
        for p in assembled_paths:
            is_subpath = any(
                p != other and any(p == other[k : k + len(p)] for k in range(len(other) - len(p) + 1))
                for other in longest_paths
            )
            if not is_subpath:
                longest_paths.append(p)

        results: List[ReconstructedThreatContig] = []

        # Step 3: Stitch contigs and evaluate against threat index
        for idx, path in enumerate(longest_paths):
            contig_seq = orders_by_id[path[0]].sequence
            junctions = []
            custs = set()
            custs.add(orders_by_id[path[0]].customer_id)

            for step in range(len(path) - 1):
                cur_id = path[step]
                nxt_id = path[step + 1]
                custs.add(orders_by_id[nxt_id].customer_id)

                # find overlap details
                match = self.find_overlap(orders_by_id[cur_id].sequence, orders_by_id[nxt_id].sequence)
                if match:
                    over_seq, over_len = match
                    junctions.append({
                        "from_order": cur_id,
                        "to_order": nxt_id,
                        "overlap_length_nt": over_len,
                        "overlap_seq": over_seq,
                    })
                    contig_seq += orders_by_id[nxt_id].sequence[over_len:]

            # Screen assembled contig through biosecurity radar
            eval_res = self.detector.scan_sequence(contig_seq)
            threat_found = eval_res["threat_detected"]
            agent_name = None
            tier = "NONE"
            conf = None

            if threat_found and eval_res["hits"]:
                top_hit = eval_res["hits"][0]
                agent_name = top_hit["agent_name"]
                tier = top_hit["regulatory_tier"]
                conf = top_hit["confidence"]

            status = (
                f"ALERT: Distributed fragment evasion matched {agent_name} ({tier})"
                if threat_found
                else f"Benign composite assembly ({len(contig_seq)} nt across {len(path)} orders)"
            )

            contig = ReconstructedThreatContig(
                contig_id=f"CONTIG-STITCH-{idx+1:03d}",
                assembled_sequence=contig_seq,
                assembled_length_nt=len(contig_seq),
                participating_order_ids=path,
                participating_customers=sorted(list(custs)),
                overlap_junctions=junctions,
                threat_detected=threat_found,
                agent_name=agent_name,
                regulatory_tier=tier,
                confidence=conf,
                status_summary=status,
            )
            results.append(contig)

        return results


# Global singleton instance
assembly_scanner = SplitOrderGraphAssembler()
