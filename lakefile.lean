import Lake

open Lake DSL

package ixyk

lean_lib Ixyk

lean_exe «ixyk-golden-check» where
  root := `Ixyk.GoldenCheck
