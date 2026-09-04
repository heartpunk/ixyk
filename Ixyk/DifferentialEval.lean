import Ixyk.Artifact

def main : IO UInt32 := do
  let input ← IO.getStdin
  let output ← IO.getStdout
  repeat
    let line ← input.getLine
    if line.isEmpty then break
    let response := match Lean.Json.parse line >>= Ixyk.Artifact.evalRequest with
      | .ok value => Lean.Json.mkObj [("value", value)]
      | .error message => Lean.Json.mkObj [("error", Lean.toJson message)]
    output.putStrLn response.compress
    output.flush
  pure 0
