"""
TransWAF - Attention Rollout Explainability Module
Computes per-token importance scores using attention rollout,
allowing analysts to see exactly which tokens triggered a classification.

Reference: Abnar & Zuidema, "Quantifying Attention Flow in Transformers", ACL 2020
"""

import torch
import numpy as np
from typing import Optional


class AttentionRollout:
    """
    Computes attention rollout across all transformer layers to produce
    a single per-token saliency score from a DistilBERT model.

    Attention rollout addresses the problem that individual layer attention
    heads may not be interpretable — rollout propagates information flow
    through all layers, starting from the identity (raw input → output).
    """

    def __init__(self, discard_ratio: float = 0.9):
        """
        Args:
            discard_ratio: Fraction of lowest-weight attention values to
                           zero out per head (noise reduction). Range: [0, 1).
        """
        self.discard_ratio = discard_ratio

    def rollout(self, attentions: tuple, input_ids: torch.Tensor) -> np.ndarray:
        """
        Compute the rolled-out attention from all layers.

        Args:
            attentions: Tuple of attention tensors from model output.
                        Each: (batch, heads, seq_len, seq_len)
            input_ids:  Token IDs tensor (batch, seq_len)

        Returns:
            1D numpy array of shape (seq_len,) with normalized importance scores.
        """
        # Average over heads and take first batch item
        result = torch.eye(attentions[0].size(-1))  # Identity matrix

        for attention in attentions:
            # attention shape: (batch, heads, seq, seq) — take first batch item
            attn = attention[0].mean(dim=0)  # (seq, seq)

            # Discard lowest attention values (noise reduction)
            flat = attn.view(-1)
            n_discard = int(self.discard_ratio * flat.size(0))
            if n_discard > 0:
                threshold = flat.kthvalue(n_discard).values
                attn = torch.where(attn <= threshold, torch.zeros_like(attn), attn)

            # Symmetrize (attention can attend in both directions)
            attn = attn + torch.eye(attn.size(0))
            attn = attn / attn.sum(dim=-1, keepdim=True).clamp(min=1e-8)

            # Rollout: multiply attention maps layer by layer
            result = torch.matmul(attn, result)

        # Return [CLS] row — how much the [CLS] token attends to each position
        cls_attention = result[0].detach().numpy()

        # Normalize to [0, 1]
        if cls_attention.max() > cls_attention.min():
            cls_attention = (cls_attention - cls_attention.min()) / (
                cls_attention.max() - cls_attention.min()
            )

        return cls_attention

    def get_token_saliency(
        self,
        tokens: list[str],
        attention_weights: np.ndarray,
        top_k: int = 15,
    ) -> dict:
        """
        Map rollout scores back to human-readable tokens.

        Args:
            tokens: List of decoded token strings
            attention_weights: 1D array of per-token importance
            top_k: Maximum number of tokens to return

        Returns:
            Dict mapping token → saliency score (sorted descending), top_k only
        """
        # Skip special tokens
        skip_tokens = {"[CLS]", "[SEP]", "[PAD]", "<s>", "</s>", "<pad>"}

        scored = []
        for token, score in zip(tokens, attention_weights):
            if token in skip_tokens:
                continue
            # Merge sub-word tokens (## prefix in WordPiece)
            clean_token = token.replace("##", "").strip()
            if clean_token:
                scored.append((clean_token, float(score)))

        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)

        # Take top_k unique tokens
        seen = set()
        result = {}
        for token, score in scored:
            if token not in seen and len(result) < top_k:
                result[token] = round(score, 4)
                seen.add(token)

        return result
