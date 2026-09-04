-- SPDX-FileCopyrightText: 2026 Sophie Smithburg
-- SPDX-License-Identifier: GPL-3.0-or-later

import Ixyk.Artifact

private def check : List String → IO UInt32
  | [] => pure 0
  | path :: rest => do
      match Ixyk.Artifact.parse (← IO.FS.readFile path) with
      | .ok _ => check rest
      | .error message => IO.eprintln s!"{path}: {message}" *> pure 1

def main (arguments : List String) : IO UInt32 := do
  match arguments with
  | [] => IO.eprintln "usage: ixyk-golden-check MODEL.json..." *> pure 2
  | paths => check paths
