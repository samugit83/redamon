rule tc_fixture_webshell {
  strings:
    $a = "eval("
  condition:
    $a
}
