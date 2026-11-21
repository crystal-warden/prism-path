-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Basic
/-!
# The shape of a reading against a policy's field definitions

`fits d` says a field definition accepts the value every reading holds for its name: `classifier_version` an
integer definition whose range holds `CLASSIFIER_VERSION`, the eight category fields category definitions, the
six boolean fields boolean definitions, and any other name a definition that allows absence (no reading holds
it). `Theorems.boundary_accepts_every_reading` proves that a policy whose definitions all fit accepts every
reading at its system boundary; the oracle's `--policy` mode computes `fitsAll` on a shipped image.
-/

namespace Classifier

def categoryFields : List String := ["command_class", "git_op", "net_dest", "path_scope", "proc_class", "remote_class", "tool", "zone_reach"]
def boolFields : List String := ["kill_by_pattern", "path_control", "path_glob", "path_in_toolchain", "path_symlink", "path_traversal"]

def fits (d : Core.FieldDef) : Bool :=
  if d.name == "classifier_version" then d.kind == .int && d.lo ≤ (CLASSIFIER_VERSION : Int) && (CLASSIFIER_VERSION : Int) ≤ d.hi
  else if categoryFields.contains d.name then d.kind == .category
  else if boolFields.contains d.name then d.kind == .bool
  else d.absentOK

def fitsAll (defs : List Core.FieldDef) : Bool := defs.all fits

end Classifier
