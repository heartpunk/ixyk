import Lake

open Lake DSL

package ixyk

require ayxg from ".dependencies/ayxg"

lean_lib Ixyk

lean_exe «ixyk-golden-check» where
  root := `Ixyk.GoldenCheck

lean_exe «ixyk-differential-eval» where
  root := `Ixyk.DifferentialEval
