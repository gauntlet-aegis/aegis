"""White-box host: Qwen2.5-1.5B hosted in-process (raw transformers) for activation hooks.

``generate`` runs a manual greedy decode loop so we control exactly which positions feed CIFT:
  * readout #1 ("final_prompt")   = hidden state at the last prompt token (after prefill)
  * readout #2 ("first_decision") = hidden state at the first generated token (after step 1)
Both are taken from the same forward graph that produces the returned text — no double-decode
drift. Mahalanobis scoring downstream is elementwise, so nothing here needs an MPS-flaky kernel.
"""

from __future__ import annotations

import time

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from sentinel.config import Settings
from sentinel.events.schema import Mode
from sentinel.model.hooks import HookManager, hooked_layer_indices
from sentinel.model.host import GenResult, ModelHost


class WhiteBoxHost(ModelHost):
    mode = Mode.WHITEBOX

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.device = settings.device
        self.tokenizer = AutoTokenizer.from_pretrained(settings.model_id)
        self.model = AutoModelForCausalLM.from_pretrained(
            settings.model_id, torch_dtype=torch.float32
        ).to(self.device)
        self.model.eval()
        self.hooked = hooked_layer_indices(self.model.config.num_hidden_layers)
        self.hooks = HookManager(self.model, self.hooked)

    @property
    def num_hidden_layers(self) -> int:
        return self.model.config.num_hidden_layers

    def _readout_snapshot(self, position: int) -> dict[int, torch.Tensor]:
        """Grab the hidden state at ``position`` for every hooked layer from the current buffers."""
        snap: dict[int, torch.Tensor] = {}
        for li, hs in self.hooks.current().items():
            snap[li] = hs[:, position, :].squeeze(0).to("cpu")  # [hidden]
        return snap

    @torch.no_grad()
    def readout(self, messages: list[dict]) -> dict[int, torch.Tensor]:
        """Capture just the two readout positions (final prompt + first decision) — no full decode.

        Used for CIFT feature extraction over the training set; much cheaper than generate().
        """
        input_ids = self.tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt"
        ).to(self.device)
        readouts: dict[int, list[torch.Tensor]] = {li: [] for li in self.hooked}
        self.hooks.arm()
        try:
            out = self.model(input_ids, use_cache=True)  # prefill
            for li, v in self._readout_snapshot(-1).items():
                readouts[li].append(v)
            next_id = out.logits[:, -1, :].argmax(dim=-1, keepdim=True)
            self.model(next_id, past_key_values=out.past_key_values, use_cache=True)  # first decode
            for li, v in self._readout_snapshot(-1).items():
                readouts[li].append(v)
        finally:
            self.hooks.disarm()
        return {li: torch.stack(vs) for li, vs in readouts.items()}

    @torch.no_grad()
    def generate(self, messages: list[dict]) -> GenResult:
        t0 = time.perf_counter()
        input_ids = self.tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt"
        ).to(self.device)

        eos_id = self.tokenizer.eos_token_id
        readouts: dict[int, list[torch.Tensor]] = {li: [] for li in self.hooked}
        readout_kinds: list[str] = []
        generated: list[int] = []

        self.hooks.arm()
        try:
            past = None
            cur = input_ids
            for step in range(self.settings.max_new_tokens):
                out = self.model(cur, past_key_values=past, use_cache=True)
                past = out.past_key_values

                if step == 0:  # prefill -> final prompt token
                    snap = self._readout_snapshot(-1)
                    for li, v in snap.items():
                        readouts[li].append(v)
                    readout_kinds.append("final_prompt")
                elif step == 1:  # first decode -> first-decision position
                    snap = self._readout_snapshot(-1)
                    for li, v in snap.items():
                        readouts[li].append(v)
                    readout_kinds.append("first_decision")

                next_id = out.logits[:, -1, :].argmax(dim=-1, keepdim=True)
                tok = int(next_id.item())
                if tok == eos_id:
                    break
                generated.append(tok)
                cur = next_id
        finally:
            self.hooks.disarm()

        activations = {li: torch.stack(vs) for li, vs in readouts.items() if vs}  # [n_readout, hidden]
        text = self.tokenizer.decode(generated, skip_special_tokens=True)
        return GenResult(
            text=text,
            activations=activations or None,
            token_count=len(generated),
            latency_ms=(time.perf_counter() - t0) * 1000,
            readout_kinds=readout_kinds,
        )
