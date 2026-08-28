// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//
// The C++ embed proof: the certified C11 interpreter (prismpath-hw/interp.c) compiled
// into a C++17 application unmodified, wrapped in ~40 lines of RAII, then held to the
// standard every substrate is held to — corpus replay. The fixture carries the certified
// CLI's own verdicts for all 4568 events of the frozen hysteresis sequence oracle; this
// process must agree on every one, or it exits nonzero. Same source, two
// materializations, byte-identical decisions: that is what makes the port provable
// rather than plausible.
//
// Scope: this embeds the EVALUATOR. Signature and envelope verification run upstream
// (the pack loader); an autonomy stack embedding this keeps that boundary.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "interp.h"

namespace prismpath {

// One decision: which edge matched and where the walk goes. A clean no-match is not an
// error for a stateful policy; it is the deadband hold.
struct Decision {
    int edge;
    uint16_t target;
};

class PolicyImage {
  public:
    explicit PolicyImage(const std::string &path)
        : im_(ppt_image_open(path.c_str()), &ppt_image_close) {}

    uint16_t start() const { return ppt_image_start(im_.get()); }
    uint16_t n_fields() const { return ppt_image_n_fields(im_.get()); }
    uint16_t n_nodes() const { return ppt_image_n_nodes(im_.get()); }

    // evaluate(node, regs): the priority encoder. std::nullopt is a clean no-match.
    std::optional<Decision> evaluate(uint16_t node, const std::vector<ppt_reg> &regs) const {
        uint16_t target = 0;
        int e = ppt_evaluate_node(im_.get(), node, regs.data(), &target);
        if (e == PPT_EVAL_NONE) return std::nullopt;
        if (e == PPT_EVAL_BAD_NODE) throw std::out_of_range("node out of range");
        return Decision{e, target};
    }

  private:
    std::unique_ptr<ppt_image, void (*)(ppt_image *)> im_;
};

}  // namespace prismpath

namespace {

#pragma pack(push, 1)
struct FixtureHeader {
    char magic[4];
    uint16_t version, n_fields;
    uint32_t n_events;
    uint8_t image_sha256[32];
};
struct FixtureRecord {
    uint16_t node_in;
    int32_t ty, val;
    int16_t expected_edge;
    uint16_t node_out;
};
#pragma pack(pop)

}  // namespace

int main(int argc, char **argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: ppt_replay <image.ppt> <fixture.bin>\n");
        return 2;
    }
    prismpath::PolicyImage image(argv[1]);

    std::ifstream f(argv[2], std::ios::binary);
    FixtureHeader hdr{};
    f.read(reinterpret_cast<char *>(&hdr), sizeof hdr);
    if (!f || std::memcmp(hdr.magic, "PPTF", 4) != 0 || hdr.version != 1) {
        std::fprintf(stderr, "bad fixture\n");
        return 2;
    }
    if (hdr.n_fields != image.n_fields()) {
        std::fprintf(stderr, "fixture/image field count mismatch\n");
        return 2;
    }

    uint32_t agree = 0, holds = 0;
    for (uint32_t i = 0; i < hdr.n_events; i++) {
        FixtureRecord r{};
        f.read(reinterpret_cast<char *>(&r), sizeof r);
        if (!f) {
            std::fprintf(stderr, "truncated fixture at record %u\n", i);
            return 2;
        }
        std::vector<ppt_reg> regs = {{r.ty, r.val}};
        auto d = image.evaluate(r.node_in, regs);
        int edge = d ? d->edge : PPT_EVAL_NONE;
        uint16_t node_out = d ? d->target : r.node_in;  // no-match = the deadband hold
        if (edge != r.expected_edge || node_out != r.node_out) {
            std::fprintf(stderr,
                         "DIVERGENCE at record %u: in=%u val=%d -> edge %d node %u, "
                         "certified CLI said edge %d node %u\n",
                         i, r.node_in, r.val, edge, node_out, r.expected_edge, r.node_out);
            return 1;
        }
        agree++;
        if (!d) holds++;
    }

    std::printf("EMBED PROOF PASS: %u/%u events byte-identical to the certified CLI "
                "(%u no-match events)\n", agree, hdr.n_events, holds);
    std::printf("policy: start=%u nodes=%u fields=%u — the resident-FSM hysteresis "
                "policy, evaluated in-process from C++\n",
                image.start(), image.n_nodes(), image.n_fields());
    return 0;
}
