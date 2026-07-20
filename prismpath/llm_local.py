"""A local LLM generate() for the agent + router's LLM-fallback. Self-contained (no repe dep).

Handles plain bf16 models (Qwen2.5-Coder-7B) AND quantized ones (Qwen3.6-27B-NVFP4 via
compressed-tensors), plus thinking models (enable_thinking toggle). Swappable: any
`generate_fn(prompt)->str` works, so this could point at a local vLLM endpoint or an API later.

Env: PRISMPATH_LLM (model id) · PRISMPATH_LLM_DEVICE (cuda|cpu) · PRISMPATH_LLM_MIN_FREE_GB ·
PRISMPATH_LLM_THINKING (0/1 — keep 0 for short routed answers).
"""
from __future__ import annotations

import os

_MODEL = os.environ.get("PRISMPATH_LLM", "Qwen/Qwen2.5-Coder-7B-Instruct")
_MIN_FREE_GB = float(os.environ.get("PRISMPATH_LLM_MIN_FREE_GB", "18"))
_DEVICE = os.environ.get("PRISMPATH_LLM_DEVICE", "cuda")
_THINKING = os.environ.get("PRISMPATH_LLM_THINKING", "0") not in ("0", "false", "False", "")
_state = {"tok": None, "model": None}


def _load():
    if _state["model"] is not None:
        return
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, AutoConfig
    cfg = AutoConfig.from_pretrained(_MODEL, trust_remote_code=True)
    quantized = bool(getattr(cfg, "quantization_config", None))
    if _DEVICE == "cuda":
        free, _ = torch.cuda.mem_get_info()
        if free / 1e9 < _MIN_FREE_GB:
            raise RuntimeError(f"Only {free/1e9:.1f} GB GPU free (< {_MIN_FREE_GB}); refusing "
                               f"to load {_MODEL}. Free GPU / set PRISMPATH_LLM_MIN_FREE_GB / "
                               f"PRISMPATH_LLM_DEVICE=cpu.")
    _state["tok"] = AutoTokenizer.from_pretrained(_MODEL, trust_remote_code=True)
    if quantized:
        _state["model"] = AutoModelForCausalLM.from_pretrained(
            _MODEL, device_map=_DEVICE, dtype="auto", trust_remote_code=True).eval()
    else:
        _state["model"] = AutoModelForCausalLM.from_pretrained(
            _MODEL, dtype=torch.bfloat16, trust_remote_code=True).to(_DEVICE).eval()
    print(f"[llm_local] loaded {_MODEL} ({'quantized' if quantized else 'bf16'}, "
          f"thinking={_THINKING}) on {_state['model'].device}")


def generate(prompt: str, max_new_tokens: int = 8) -> str:
    import torch
    _load()
    tok, model = _state["tok"], _state["model"]
    msgs = [{"role": "user", "content": prompt}]
    try:
        text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True,
                                       enable_thinking=_THINKING)
    except TypeError:
        text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    enc = tok(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**enc, max_new_tokens=max_new_tokens, do_sample=False,
                             pad_token_id=tok.eos_token_id)
    return tok.decode(out[0, enc["input_ids"].shape[1]:], skip_special_tokens=True).strip()
