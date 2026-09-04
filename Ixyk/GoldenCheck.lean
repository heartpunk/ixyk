-- SPDX-FileCopyrightText: 2026 Sophie Smithburg
-- SPDX-License-Identifier: GPL-3.0-or-later

import Ixyk.Artifact

def main (arguments : List String) : IO UInt32 := do
  match arguments with
  | [path] =>
      match Ixyk.Artifact.parseAndElaborate (← IO.FS.readFile path) with
      | .ok _ => pure 0
      | .error message => IO.eprintln message *> pure 1
  | _ => IO.eprintln "usage: ixyk-golden-check MODEL.json" *> pure 2
