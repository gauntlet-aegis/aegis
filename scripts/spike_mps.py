"""Day-0 MPS gate (PRD risk #1).

Proves the whole white-box premise before anyone builds CIFT on top:
load Qwen2.5-1.5B-Instruct fp32 on MPS, register a forward hook on one decoder block,
run a 1-token prefill, and print the captured hidden-state shape.

Success = a ``[1, seq, 1536]`` shape prints with no kernel crash.

Run:  PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python scripts/spike_mps.py
"""

from __future__ import annotations

import sys

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_ID = "Qwen/Qwen2.5-1.5B-Instruct"


def pick_device() -> str:
    if torch.backends.mps.is_available():
        return "mps"
    print("WARNING: MPS unavailable, falling back to CPU (slow but viable).")
    return "cpu"


def main() -> int:
    device = pick_device()
    print(f"device              : {device}")
    print(f"mps available       : {torch.backends.mps.is_available()}")

    print(f"loading {MODEL_ID} (fp32)... first run downloads ~3.1 GB safetensors")
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, torch_dtype=torch.float32).to(device)
    model.eval()

    L = model.config.num_hidden_layers
    hidden = model.config.hidden_size
    print(f"num_hidden_layers   : {L}")
    print(f"hidden_size         : {hidden}")
    print(f"param device        : {next(model.parameters()).device}")

    # Hook one mid-stack decoder block.
    captured: dict[str, torch.Tensor] = {}
    layer_idx = L // 2

    def hook(_module, _inputs, output):
        hs = output[0] if isinstance(output, tuple) else output
        captured["hs"] = hs.detach()

    handle = model.model.layers[layer_idx].register_forward_hook(hook)

    # Single prefill forward pass (this is the readout-capture mechanism CIFT will use).
    messages = [{"role": "user", "content": "Say hello in one word."}]
    inputs = tok.apply_chat_template(
        messages, add_generation_prompt=True, return_tensors="pt"
    ).to(device)
    with torch.no_grad():
        out = model(inputs, use_cache=True)
    handle.remove()

    next_id = out.logits[:, -1, :].argmax(dim=-1)
    next_tok = tok.decode(next_id)

    hs = captured.get("hs")
    print(f"hooked layer        : {layer_idx}")
    print(f"hidden-state shape  : {tuple(hs.shape) if hs is not None else None}")
    print(f"final-token vec     : {tuple(hs[:, -1, :].shape) if hs is not None else None}")
    print(f"first generated tok : {next_tok!r}")

    ok = hs is not None and hs.shape[-1] == hidden and hs.shape[0] == 1
    print("GATE:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
