# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Tests for llm_local module."""

import pytest
from prismpath.routing import llm_local


class StubTensor:
    def __init__(self, shape=(1, 5)):
        self.shape = shape

    def to(self, device):
        return self

    def __getitem__(self, item):
        return self


class StubBatchEncoding(dict):
    def to(self, device):
        return self


class StubTokenizer:
    def __init__(self, raise_on_thinking=False):
        self.raise_on_thinking = raise_on_thinking
        self.eos_token_id = 2
        self.last_applied_msgs = None

    def apply_chat_template(self, msgs, tokenize=False, add_generation_prompt=True, enable_thinking=False):
        if self.raise_on_thinking and enable_thinking:
            raise TypeError("unexpected keyword argument 'enable_thinking'")
        self.last_applied_msgs = msgs
        return "formatted prompt"

    def __call__(self, text, return_tensors=None):
        return StubBatchEncoding({"input_ids": StubTensor()})

    def decode(self, ids, skip_special_tokens=True):
        return "  hello world response  "


class StubModel:
    def __init__(self):
        self.device = "cpu"
        self.last_generate_kwargs = None

    def generate(self, **kwargs):
        self.last_generate_kwargs = kwargs
        return StubTensor((1, 10))

    def eval(self):
        return self

    def to(self, device):
        return self


def test_generate_with_stub_model(monkeypatch):
    tok = StubTokenizer()
    model = StubModel()

    monkeypatch.setitem(llm_local._state, "tok", tok)
    monkeypatch.setitem(llm_local._state, "model", model)
    monkeypatch.setattr(llm_local, "_load", lambda: None)

    out = llm_local.generate("explain semver", max_new_tokens=16)

    assert out == "hello world response"
    assert tok.last_applied_msgs == [{"role": "user", "content": "explain semver"}]
    assert model.last_generate_kwargs["max_new_tokens"] == 16
    assert model.last_generate_kwargs["do_sample"] is False


def test_generate_handles_chat_template_type_error(monkeypatch):
    tok = StubTokenizer(raise_on_thinking=True)
    model = StubModel()

    monkeypatch.setitem(llm_local._state, "tok", tok)
    monkeypatch.setitem(llm_local._state, "model", model)
    monkeypatch.setattr(llm_local, "_load", lambda: None)
    monkeypatch.setattr(llm_local, "_THINKING", True)

    out = llm_local.generate("hello prompt")
    assert out == "hello world response"


def test_load_gpu_mem_check_refusal(monkeypatch):
    import torch

    monkeypatch.setitem(llm_local._state, "tok", None)
    monkeypatch.setitem(llm_local._state, "model", None)
    monkeypatch.setattr(llm_local, "_DEVICE", "cuda")
    monkeypatch.setattr(llm_local, "_MIN_FREE_GB", 100.0)

    # 4 GB free out of 16 GB total
    monkeypatch.setattr(torch.cuda, "mem_get_info", lambda: (4 * 1024 * 1024 * 1024, 16 * 1024 * 1024 * 1024))

    with pytest.raises(RuntimeError, match="refusing to load"):
        llm_local._load()


def test_load_quantized_and_bf16_paths(monkeypatch):
    import transformers

    class DummyConfig:
        def __init__(self, quantized):
            self.quantization_config = {"quant_method": "fp4"} if quantized else None

    # Test quantized branch
    monkeypatch.setitem(llm_local._state, "tok", None)
    monkeypatch.setitem(llm_local._state, "model", None)
    monkeypatch.setattr(llm_local, "_DEVICE", "cpu")

    monkeypatch.setattr(transformers.AutoConfig, "from_pretrained", lambda *a, **k: DummyConfig(quantized=True))
    monkeypatch.setattr(transformers.AutoTokenizer, "from_pretrained", lambda *a, **k: StubTokenizer())
    monkeypatch.setattr(transformers.AutoModelForCausalLM, "from_pretrained", lambda *a, **k: StubModel())

    llm_local._load()
    assert llm_local._state["tok"] is not None
    assert llm_local._state["model"] is not None

    # Test bf16 branch
    monkeypatch.setitem(llm_local._state, "tok", None)
    monkeypatch.setitem(llm_local._state, "model", None)
    monkeypatch.setattr(transformers.AutoConfig, "from_pretrained", lambda *a, **k: DummyConfig(quantized=False))

    llm_local._load()
    assert llm_local._state["tok"] is not None
    assert llm_local._state["model"] is not None
